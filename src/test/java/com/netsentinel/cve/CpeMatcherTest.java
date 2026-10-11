package com.netsentinel.cve;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CpeMatcherTest {

    @Test
    void versionComparison() {
        assertTrue(CpeMatcher.compareVersions("2.10.0", "2.9.0") > 0);
        assertEquals(0, CpeMatcher.compareVersions("1.0", "1.0.0"));
        assertTrue(CpeMatcher.compareVersions("1.1.1k", "1.1.1l") < 0);
    }

    /** Accuracy on the hand-labelled set in cpe_labels.csv; prints the figure for the paper. */
    @Test
    void handLabelledAccuracy() throws IOException {
        List<String> lines = Files.readAllLines(Path.of("src/test/resources/cpe_labels.csv"));
        int total = 0, correct = 0;
        StringBuilder wrong = new StringBuilder();
        for (String line : lines) {
            if (line.isBlank() || line.startsWith("#")) continue;
            String[] f = line.split(";");
            boolean expected = f[2].trim().equals("match");
            boolean actual = CpeMatcher.matches(f[0], f[1]);
            total++;
            if (expected == actual) correct++;
            else wrong.append("\n  ").append(line).append("  -> got ").append(actual);
        }
        System.out.printf("CPE matching accuracy: %d/%d = %.1f%%%n", correct, total, 100.0 * correct / total);
        assertEquals(total, correct, "Mismatched cases:" + wrong);
    }
}
