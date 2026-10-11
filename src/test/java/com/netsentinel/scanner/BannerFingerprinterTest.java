package com.netsentinel.scanner;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Hand-labelled banner samples in the formats real services emit. Expected value = CPE, or "" when the
 * response does not reveal a version (the fingerprinter must then return nothing rather than guess).
 */
class BannerFingerprinterTest {

    private static final Map<String, String> CASES = new LinkedHashMap<>();

    static {
        // --- positives
        CASES.put("HTTP/1.1 200 OK\r\nDate: Mon, 12 Oct 2026 10:00:00 GMT\r\nServer: Apache/2.4.49 (Unix)\r\nContent-Length: 45\r\n\r\n",
                "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*");
        CASES.put("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\n\r\n",
                "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*");
        CASES.put("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)\r\n\r\n",
                "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*");
        CASES.put("HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\nX-Powered-By: ASP.NET\r\n\r\n",
                "cpe:2.3:a:microsoft:internet_information_services:10.0:*:*:*:*:*:*:*");
        CASES.put("HTTP/1.1 403 Forbidden\r\nContent-Type: text/html;charset=utf-8\r\nX-Jenkins: 2.346.1\r\nX-Jenkins-Session: abc\r\n\r\n",
                "cpe:2.3:a:jenkins:jenkins:2.346.1:*:*:*:*:*:*:*");
        CASES.put("$2548\r\n# Server\r\nredis_version:6.2.6\r\nredis_git_sha1:00000000\r\nredis_mode:standalone\r\n",
                "cpe:2.3:a:redis:redis:6.2.6:*:*:*:*:*:*:*");
        CASES.put("VERSION 1.6.9\r\n",
                "cpe:2.3:a:memcached:memcached:1.6.9:*:*:*:*:*:*:*");
        CASES.put("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n",
                "cpe:2.3:a:openbsd:openssh:8.2:p1:*:*:*:*:*:*");
        CASES.put("SSH-2.0-OpenSSH_9.6\r\n",
                "cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*");
        CASES.put("220 ProFTPD 1.3.5 Server (Debian) [::ffff:10.0.0.5]\r\n",
                "cpe:2.3:a:proftpd:proftpd:1.3.5:*:*:*:*:*:*:*");
        CASES.put("220 (vsFTPd 3.0.3)\r\n",
                "cpe:2.3:a:vsftpd_project:vsftpd:3.0.3:*:*:*:*:*:*:*");
        CASES.put("J\u0000\u0000\u0000\n5.7.30\u0000\u0008\u0000\u0000\u0000abcdefgh\u0000",
                "cpe:2.3:a:oracle:mysql:5.7.30:*:*:*:*:*:*:*");
        CASES.put("P\u0000\u0000\u0000\n5.5.5-10.3.37-MariaDB-1:10.3.37+maria~focal\u0000\u0009\u0000",
                "cpe:2.3:a:mariadb:mariadb:10.3.37:*:*:*:*:*:*:*");
        CASES.put("HTTP/1.0 200 OK\r\ncontent-type: application/json\r\n\r\n{\n  \"name\" : \"node-1\",\n  \"cluster_name\" : \"docker-cluster\",\n"
                + "  \"version\" : {\n    \"number\" : \"7.17.0\",\n    \"build_flavor\" : \"default\",\n    \"lucene_version\" : \"8.11.1\"\n  }\n}",
                "cpe:2.3:a:elastic:elasticsearch:7.17.0:*:*:*:*:*:*:*");
        // --- negatives: no version disclosed, or not a recognised product
        CASES.put("HTTP/1.1 200 OK\r\nServer: Apache\r\n\r\n", "");
        CASES.put("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n", "");
        CASES.put("HTTP/1.1 200 OK\r\nServer: Apache-Coyote/1.1\r\n\r\n", "");
        CASES.put("-ERR unknown command 'GET'\r\n-ERR unknown command 'Host:'\r\n", "");
        CASES.put("+OK\r\n", "");
        CASES.put("ERROR\r\n", "");
        CASES.put("SSH-2.0-dropbear_2020.81\r\n", "");
        CASES.put("", "");
        CASES.put("\u0000\u0001\u0002\u0003 binary noise", "");
    }

    @Test
    void handLabelledAccuracy() {
        int correct = 0;
        StringBuilder wrong = new StringBuilder();
        for (var e : CASES.entrySet()) {
            Optional<BannerFingerprinter.Detected> d = BannerFingerprinter.identify(e.getKey());
            String actual = d.map(BannerFingerprinter.Detected::cpe).orElse("");
            if (actual.equals(e.getValue())) correct++;
            else wrong.append("\n  ").append(e.getKey().replace("\r\n", "|").replace("\n", "|"), 0,
                    Math.min(60, e.getKey().length())).append(" -> ").append(actual).append(" (expected ").append(e.getValue()).append(")");
        }
        System.out.printf("Banner->CPE accuracy: %d/%d = %.1f%%%n", correct, CASES.size(), 100.0 * correct / CASES.size());
        assertEquals(CASES.size(), correct, "mismatches:" + wrong);
    }

    @Test
    void cpeMatchesTheMatcherAndOfflineDatabase() {
        // the generated CPE must be matchable by the CVE database layer
        var d = BannerFingerprinter.identify("Server: Apache/2.4.49 (Unix)").orElseThrow();
        assertTrue(com.netsentinel.cve.CpeMatcher.matches(d.cpe(), "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"));
        assertTrue(com.netsentinel.cve.CpeMatcher.matches(d.cpe(),
                "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*#>=2.4.0,<2.4.51"));
    }
}
