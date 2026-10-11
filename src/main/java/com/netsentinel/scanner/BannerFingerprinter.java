package com.netsentinel.scanner;

import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Maps a service banner / probe response to a product, version and CPE 2.3 string.
 *
 * <p>Rules are matched in order against the full response text (headers + body prefix, or the raw
 * greeting bytes decoded as ISO-8859-1). Only versions that appear verbatim in the response are
 * reported, so a hidden version produces no CPE rather than a guess.</p>
 */
public final class BannerFingerprinter {

    /** A recognised product. {@code update} is the CPE update field (e.g. "p1" for OpenSSH 8.2p1) or "*". */
    public record Detected(String vendor, String product, String version, String update) {
        public String cpe() {
            return "cpe:2.3:a:%s:%s:%s:%s:*:*:*:*:*:*".formatted(vendor, product, version, update);
        }
    }

    private record Rule(Pattern pattern, String vendor, String product) {}

    private static Rule rule(String regex, String vendor, String product) {
        return new Rule(Pattern.compile(regex, Pattern.CASE_INSENSITIVE | Pattern.DOTALL), vendor, product);
    }

    private static final String V = "(\\d+(?:\\.\\d+)+)";

    private static final List<Rule> RULES = List.of(
            rule("Server:\\s*Apache/" + V, "apache", "http_server"),
            rule("Server:\\s*nginx/" + V, "f5", "nginx"),
            rule("Server:\\s*Microsoft-IIS/" + V, "microsoft", "internet_information_services"),
            rule("X-Jenkins:\\s*" + V, "jenkins", "jenkins"),
            rule("redis_version:" + V, "redis", "redis"),
            rule("(?:^|\\r?\\n)VERSION " + V, "memcached", "memcached"),
            rule("(?:^|\\r?\\n)220[ -]ProFTPD " + V, "proftpd", "proftpd"),
            rule("(?:^|\\r?\\n)220 \\(vsFTPd " + V + "\\)", "vsftpd_project", "vsftpd"),
            rule("\"cluster_name\".*?\"number\"\\s*:\\s*\"" + V + "\"", "elastic", "elasticsearch"),
            rule("\"number\"\\s*:\\s*\"" + V + "\".*?\"lucene_version\"", "elastic", "elasticsearch")
    );

    private static final Pattern OPENSSH = Pattern.compile("SSH-\\d\\.\\d+-OpenSSH_(\\d+(?:\\.\\d+)*)(p\\d+)?");
    // MySQL/MariaDB handshake: protocol byte 0x0a, then NUL-terminated server version string
    private static final Pattern SQL_GREETING = Pattern.compile("\\u000a(\\d+\\.\\d+\\.\\d+[^\\u0000]{0,40})\\u0000");

    private BannerFingerprinter() {}

    public static Optional<Detected> identify(String response) {
        if (response == null || response.isEmpty()) return Optional.empty();

        Matcher ssh = OPENSSH.matcher(response);
        if (ssh.find()) {
            return Optional.of(new Detected("openbsd", "openssh", ssh.group(1), ssh.group(2) != null ? ssh.group(2) : "*"));
        }
        for (Rule r : RULES) {
            Matcher m = r.pattern().matcher(response);
            if (m.find()) return Optional.of(new Detected(r.vendor(), r.product(), m.group(1), "*"));
        }
        Matcher sql = SQL_GREETING.matcher(response);
        if (sql.find()) {
            // MariaDB prefixes its real version with "5.5.5-" for replication-protocol compatibility
            String raw = sql.group(1).replaceFirst("^5\\.5\\.5-", "");
            String version = raw.replaceAll("^(\\d+\\.\\d+\\.\\d+).*$", "$1");
            boolean maria = raw.toLowerCase().contains("mariadb");
            return Optional.of(maria ? new Detected("mariadb", "mariadb", version, "*")
                                     : new Detected("oracle", "mysql", version, "*"));
        }
        return Optional.empty();
    }
}
