package com.netsentinel;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

/**
 * NetSentinel-AI: Autonomous Network Vulnerability Assessment & Path Prediction Engine.
 *
 * <p>A proactive vulnerability assessment platform that scans target network assets,
 * maps software configurations to known CVEs, generates a topological attack graph,
 * predicts multi-hop compromise chains using machine learning, and synthesizes
 * automated remediation playbooks.</p>
 *
 * <p>Built natively on Java 21 LTS with Project Loom virtual threads,
 * JGraphT for graph analysis, and Deeplearning4j for JVM-native AI.</p>
 */
@SpringBootApplication
@EnableAsync
public class NetSentinelApplication {

    public static void main(String[] args) {
        System.out.println("""
            
            ╔══════════════════════════════════════════════════════════════╗
            ║                                                            ║
            ║   ███╗   ██╗███████╗████████╗███████╗███████╗███╗   ██╗   ║
            ║   ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝████╗  ██║   ║
            ║   ██╔██╗ ██║█████╗     ██║   ███████╗█████╗  ██╔██╗ ██║   ║
            ║   ██║╚██╗██║██╔══╝     ██║   ╚════██║██╔══╝  ██║╚██╗██║   ║
            ║   ██║ ╚████║███████╗   ██║   ███████║███████╗██║ ╚████║   ║
            ║   ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═══╝   ║
            ║                    ╔═╗╦                                     ║
            ║                    ╠═╣║                                     ║
            ║                    ╩ ╩╩                                     ║
            ║                                                            ║
            ║   Autonomous Network Vulnerability Assessment Engine       ║
            ║   Java 21 LTS | Spring Boot 3.2 | JGraphT | DL4J          ║
            ║                                                            ║
            ╚══════════════════════════════════════════════════════════════╝
            """);
        SpringApplication.run(NetSentinelApplication.class, args);
    }
}
