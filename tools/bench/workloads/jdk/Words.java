import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/** Text generated in chunks, split with a regular expression and counted
 *  by word across threads (parallel streams over a ConcurrentHashMap). */
final class Words {
    private static final String[] SYLLABLES = {
        "ka", "lo", "mi", "ne", "ru", "sa", "to", "vi", "ze", "qu", "ar", "en",
    };
    private static final Pattern WORD = Pattern.compile("[a-z]+");

    static String chunk(int index, int words) {
        Rng rng = new Rng(index * 7919L + 1);
        StringBuilder text = new StringBuilder(words * 8);
        for (int w = 0; w < words; w++) {
            int length = 1 + rng.below(3);
            for (int s = 0; s < length; s++) {
                text.append(SYLLABLES[rng.below(SYLLABLES.length)]);
            }
            text.append(rng.below(10) == 0 ? ". " : " ");
        }
        return text.toString();
    }

    static String run(int chunks, int words) {
        Map<String, Long> counts = new ConcurrentHashMap<>();
        IntStream.range(0, chunks).parallel().forEach(i -> {
            Matcher m = WORD.matcher(chunk(i, words));
            while (m.find()) {
                counts.merge(m.group(), 1L, Long::sum);
            }
        });
        List<Map.Entry<String, Long>> top = counts.entrySet().stream()
            .sorted(Map.Entry.<String, Long>comparingByValue(Comparator.reverseOrder())
                .thenComparing(Map.Entry.comparingByKey()))
            .limit(5)
            .collect(Collectors.toList());
        long total = counts.values().stream().mapToLong(Long::longValue).sum();
        return "words: " + total + " in " + counts.size() + " kinds, most "
            + top.stream().map(e -> e.getKey() + "=" + e.getValue()).collect(Collectors.joining(" "));
    }
}
