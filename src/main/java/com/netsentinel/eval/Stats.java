package com.netsentinel.eval;

import java.util.List;

/** Mean, standard deviation and a 95% confidence interval (Student t) for a sample. */
public final class Stats {

    // two-sided 95% critical values of Student's t for df = 1..30
    private static final double[] T95 = {
            12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228,
            2.201, 2.179, 2.160, 2.145, 2.131, 2.120, 2.110, 2.101, 2.093, 2.086,
            2.080, 2.074, 2.069, 2.064, 2.060, 2.056, 2.052, 2.048, 2.045, 2.042};

    private Stats() {}

    public static double mean(List<Double> xs) {
        return xs.stream().mapToDouble(Double::doubleValue).average().orElse(Double.NaN);
    }

    public static double sd(List<Double> xs) {
        if (xs.size() < 2) return 0;
        double m = mean(xs);
        double ss = 0;
        for (double x : xs) ss += (x - m) * (x - m);
        return Math.sqrt(ss / (xs.size() - 1));
    }

    /** Half-width of the 95% confidence interval of the mean. */
    public static double ci95(List<Double> xs) {
        int n = xs.size();
        if (n < 2) return 0;
        int df = n - 1;
        double t = df <= 30 ? T95[df - 1] : 1.96 + 0.082 * 30.0 / df;
        return t * sd(xs) / Math.sqrt(n);
    }

    /** Kendall's tau-b between two rankings given as score vectors (O(n^2)). */
    public static double kendallTauB(double[] x, double[] y) {
        int n = x.length;
        long concordant = 0, discordant = 0, tiesX = 0, tiesY = 0;
        for (int i = 0; i < n; i++) {
            for (int j = i + 1; j < n; j++) {
                double dx = x[i] - x[j], dy = y[i] - y[j];
                if (dx == 0 && dy == 0) continue;
                if (dx == 0) tiesX++;
                else if (dy == 0) tiesY++;
                else if (dx * dy > 0) concordant++;
                else discordant++;
            }
        }
        double denom = Math.sqrt((double) (concordant + discordant + tiesX) * (concordant + discordant + tiesY));
        return denom == 0 ? Double.NaN : (concordant - discordant) / denom;
    }
}
