package com.analyzer.service.fix;

import com.sun.source.tree.ClassTree;
import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.tree.MethodTree;
import com.sun.source.tree.Tree;
import com.sun.source.tree.VariableTree;
import com.sun.source.util.JavacTask;

import javax.lang.model.element.Modifier;
import javax.tools.JavaFileObject;
import javax.tools.SimpleJavaFileObject;
import javax.tools.ToolProvider;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * Conservative source-level API comparison. The parser ONLY parses text; it never loads or runs
 * classes and does not invoke annotation processors. This is not a binary ABI verifier.
 */
final class FixApiCompatibility {
    private FixApiCompatibility() { }

    record Check(FixValidationService.Status status, String details) { }

    static Check compare(String filename, String before, String after) {
        try {
            Snapshot original = inspect(filename, before);
            Snapshot candidate = inspect(filename, after);
            if (!original.packageName.equals(candidate.packageName)) {
                return new Check(FixValidationService.Status.FAILED,
                        "Пакет изменён: " + original.packageName + " → " + candidate.packageName);
            }
            Set<String> missing = new TreeSet<>(original.contracts);
            missing.removeAll(candidate.contracts);
            if (!missing.isEmpty()) {
                List<String> entries = new ArrayList<>(missing);
                String msg = "Удалены/изменены элементы публичного API: "
                        + String.join("; ", entries.subList(0, Math.min(entries.size(), 8)));
                return new Check(FixValidationService.Status.FAILED, msg);
            }
            return new Check(FixValidationService.Status.PASSED,
                    "Имена типов и исходные публичные/защищённые объявления сохранены. "
                            + "Это не доказывает совместимость поведения или бинарного API.");
        } catch (Exception ex) {
            return new Check(FixValidationService.Status.NOT_CHECKED,
                    "Не удалось проверить структуру исходников: " + ex.getMessage());
        }
    }

    private record Snapshot(String packageName, Set<String> contracts) { }

    private static Snapshot inspect(String filename, String source) throws Exception {
        var compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) throw new IOException("Нужен JDK 21 (не JRE)");
        JavaFileObject input = new SimpleJavaFileObject(URI.create("string:///SourceForReview.java"),
                JavaFileObject.Kind.SOURCE) {
            @Override public CharSequence getCharContent(boolean ignoreEncodingErrors) {
                return source;
            }
        };
        try (var files = compiler.getStandardFileManager(null, null, java.nio.charset.StandardCharsets.UTF_8)) {
            JavacTask task = (JavacTask) compiler.getTask(null, files, null,
                    List.of("-proc:none"), null, List.of(input));
            var parsed = task.parse().iterator();
            if (!parsed.hasNext()) throw new IOException("Пустое дерево разбора");
            CompilationUnitTree unit = parsed.next();
            String pkg = unit.getPackageName() == null ? "" : unit.getPackageName().toString();
            Set<String> contracts = new TreeSet<>();
            for (Tree t : unit.getTypeDecls()) {
                if (t instanceof ClassTree cls) addType(cls, "", true, contracts);
            }
            if (contracts.isEmpty()) throw new IOException("Не найдено объявление Java-типа");
            return new Snapshot(pkg, contracts);
        }
    }

    private static void addType(ClassTree type, String parent, boolean parentVisible,
                                Set<String> contracts) {
        String owner = parent.isEmpty() ? type.getSimpleName().toString()
                : parent + "." + type.getSimpleName();
        Set<Modifier> flags = type.getModifiers().getFlags();
        boolean visible = parentVisible && (parent.isEmpty() || flags.contains(Modifier.PUBLIC)
                || flags.contains(Modifier.PROTECTED));
        // Retain top-level types regardless of visibility to prevent accidental removal/rename.
        if (visible) {
            contracts.add("тип " + owner + " " + type.getKind() + " public="
                    + flags.contains(Modifier.PUBLIC) + " protected="
                    + flags.contains(Modifier.PROTECTED));
            contracts.add("наследование " + owner + " extends=" + stringify(type.getExtendsClause())
                    + " implements=" + type.getImplementsClause());
        }
        for (Tree member : type.getMembers()) {
            if (member instanceof ClassTree nested) {
                addType(nested, owner, visible, contracts);
            } else if (visible && member instanceof MethodTree method) {
                var mods = method.getModifiers().getFlags();
                boolean isInterface = type.getKind() == Tree.Kind.INTERFACE
                        || type.getKind() == Tree.Kind.ANNOTATION_TYPE;
                if (isInterface || mods.contains(Modifier.PUBLIC) || mods.contains(Modifier.PROTECTED)) {
                    List<String> params = method.getParameters().stream()
                            .map(p -> stringify(p.getType())).toList();
                    contracts.add("метод " + owner + "." + method.getName() + "(" + String.join(",", params)
                            + ") : " + stringify(method.getReturnType())
                            + " throws=" + method.getThrows() + " static=" + mods.contains(Modifier.STATIC));
                }
            } else if (visible && member instanceof VariableTree field) {
                Set<Modifier> mods = field.getModifiers().getFlags();
                if (mods.contains(Modifier.PUBLIC) || mods.contains(Modifier.PROTECTED)) {
                    contracts.add("поле " + owner + "." + field.getName() + " : "
                            + stringify(field.getType()) + " static=" + mods.contains(Modifier.STATIC));
                }
            }
        }
    }

    private static String stringify(Tree item) {
        return item == null ? "" : item.toString().replaceAll("\\s+", "");
    }
}
