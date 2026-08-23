package com.netsentinel.ai;

import com.netsentinel.model.CveRecord;
import com.netsentinel.model.ExploitEdge;
import com.netsentinel.model.HostNode;
import org.deeplearning4j.nn.conf.MultiLayerConfiguration;
import org.deeplearning4j.nn.conf.NeuralNetConfiguration;
import org.deeplearning4j.nn.conf.layers.DenseLayer;
import org.deeplearning4j.nn.conf.layers.OutputLayer;
import org.deeplearning4j.nn.multilayer.MultiLayerNetwork;
import org.deeplearning4j.nn.weights.WeightInit;
import org.nd4j.linalg.activations.Activation;
import org.nd4j.linalg.api.ndarray.INDArray;
import org.nd4j.linalg.dataset.DataSet;
import org.nd4j.linalg.factory.Nd4j;
import org.nd4j.linalg.learning.config.Adam;
import org.nd4j.linalg.lossfunctions.LossFunctions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.util.Random;

/**
 * Tier 3: Lateral Compromise Scorer powered by Deeplearning4j.
 *
 * <p>An in-JVM Multi-Layer Perceptron (MLP) that calculates edge exploitability
 * probabilities P(Compromise) from CVSS base scores, access complexity,
 * privilege requirements, and asset criticality.</p>
 *
 * <h3>Network Architecture:</h3>
 * <pre>
 *   Input Layer  (6 features)
 *       ↓
 *   Dense Layer  (32 neurons, ReLU)
 *       ↓
 *   Dense Layer  (16 neurons, ReLU)
 *       ↓
 *   Output Layer (1 neuron, Sigmoid) → P(Compromise)
 * </pre>
 *
 * <h3>Input Features:</h3>
 * <ol>
 *   <li>CVSS Base Score (normalized 0-1)</li>
 *   <li>Attack Complexity (LOW=1.0, HIGH=0.5)</li>
 *   <li>Privileges Required (NONE=1.0, LOW=0.6, HIGH=0.2)</li>
 *   <li>User Interaction (NONE=1.0, REQUIRED=0.5)</li>
 *   <li>Exploit in Wild (boolean 0/1)</li>
 *   <li>Asset Criticality (normalized 0-1)</li>
 * </ol>
 */
@Component
public class CompromiseScorer {

    private static final Logger log = LoggerFactory.getLogger(CompromiseScorer.class);
    private static final int NUM_FEATURES = 6;
    private static final int TRAINING_SAMPLES = 500;
    private static final int TRAINING_EPOCHS = 100;

    private MultiLayerNetwork model;

    @PostConstruct
    public void initialize() {
        log.info("▶ Initializing DL4J Compromise Scorer (MLP)...");
        buildModel();
        trainOnSyntheticData();
        log.info("✓ DL4J model trained and ready ({} parameters)",
                model.numParams());
    }

    /**
     * Scores a single exploit edge with the MLP.
     *
     * @param cve         The CVE being exploited
     * @param criticality Target host asset criticality (1-10)
     * @return Probability of successful compromise (0.0 - 1.0)
     */
    public double scoreEdge(CveRecord cve, int criticality) {
        if (cve == null) return 0.05; // Reachability-only edge

        double[] features = extractFeatures(cve, criticality);
        INDArray input = Nd4j.create(features, new int[]{1, NUM_FEATURES});
        INDArray output = model.output(input);
        return output.getDouble(0);
    }

    /**
     * Scores all edges in the graph and updates exploit probabilities.
     */
    public void scoreGraphEdges(
            org.jgrapht.graph.DirectedWeightedMultigraph<HostNode, ExploitEdge> graph) {

        log.info("▶ Scoring {} edges with DL4J MLP...", graph.edgeSet().size());
        int scored = 0;

        for (ExploitEdge edge : graph.edgeSet()) {
            HostNode target = graph.getEdgeTarget(edge);
            double probability = scoreEdge(
                    edge.getExploitedCve(),
                    target.getFingerprint().criticality()
            );
            edge.setExploitProbability(probability);

            // Update graph weight (lower weight = more exploitable = higher priority path)
            graph.setEdgeWeight(edge, 1.0 - probability + 0.001);
            scored++;
        }

        // Also update node compromise probabilities
        for (HostNode node : graph.vertexSet()) {
            double maxProb = graph.incomingEdgesOf(node).stream()
                    .mapToDouble(ExploitEdge::getExploitProbability)
                    .max().orElse(0.0);
            node.setCompromiseProbability(maxProb);
        }

        log.info("✓ Scored {} edges with ML-computed compromise probabilities", scored);
    }

    /**
     * Extracts the 6-dimensional feature vector from a CVE record.
     */
    private double[] extractFeatures(CveRecord cve, int criticality) {
        return new double[]{
                cve.cvssBaseScore() / 10.0,                          // Normalized CVSS
                cve.attackComplexity() == CveRecord.AttackComplexity.LOW ? 1.0 : 0.5,
                switch (cve.privilegesRequired()) {
                    case NONE -> 1.0;
                    case LOW -> 0.6;
                    case HIGH -> 0.2;
                },
                cve.userInteraction() == CveRecord.UserInteraction.NONE ? 1.0 : 0.5,
                cve.exploitInWild() ? 1.0 : 0.0,
                criticality / 10.0                                    // Normalized criticality
        };
    }

    /**
     * Builds the MLP network architecture.
     */
    private void buildModel() {
        MultiLayerConfiguration config = new NeuralNetConfiguration.Builder()
                .seed(42)
                .updater(new Adam(0.001))
                .weightInit(WeightInit.XAVIER)
                .list()
                .layer(0, new DenseLayer.Builder()
                        .nIn(NUM_FEATURES)
                        .nOut(32)
                        .activation(Activation.RELU)
                        .build())
                .layer(1, new DenseLayer.Builder()
                        .nIn(32)
                        .nOut(16)
                        .activation(Activation.RELU)
                        .build())
                .layer(2, new OutputLayer.Builder(LossFunctions.LossFunction.XENT)
                        .nIn(16)
                        .nOut(1)
                        .activation(Activation.SIGMOID)
                        .build())
                .build();

        model = new MultiLayerNetwork(config);
        model.init();
        log.debug("  MLP architecture: {} → 32 → 16 → 1", NUM_FEATURES);
    }

    /**
     * Trains the model on synthetic vulnerability data.
     *
     * <p>Generates training samples with known ground-truth labels based on
     * a domain-expert formula, then trains the MLP to approximate it.
     * This allows the model to generalize to unseen feature combinations.</p>
     */
    private void trainOnSyntheticData() {
        Random rng = new Random(42);
        double[][] features = new double[TRAINING_SAMPLES][NUM_FEATURES];
        double[][] labels = new double[TRAINING_SAMPLES][1];

        for (int i = 0; i < TRAINING_SAMPLES; i++) {
            // Generate random feature vectors
            double cvss = 0.1 + rng.nextDouble() * 0.9;        // 0.1-1.0
            double ac = rng.nextBoolean() ? 1.0 : 0.5;         // LOW or HIGH
            double pr = rng.nextDouble() < 0.4 ? 1.0 :
                       (rng.nextDouble() < 0.7 ? 0.6 : 0.2);   // NONE/LOW/HIGH
            double ui = rng.nextBoolean() ? 1.0 : 0.5;         // NONE or REQUIRED
            double eiw = rng.nextDouble() < 0.3 ? 1.0 : 0.0;   // 30% exploit in wild
            double crit = 0.1 + rng.nextDouble() * 0.9;        // 0.1-1.0

            features[i] = new double[]{cvss, ac, pr, ui, eiw, crit};

            // Ground truth: domain-expert composite formula
            // Higher CVSS, lower complexity, no privileges needed, exploit in wild → higher risk
            double truth = 0.3 * cvss + 0.15 * ac + 0.2 * pr + 0.05 * ui + 0.15 * eiw + 0.15 * crit;
            // Add noise
            truth += (rng.nextDouble() - 0.5) * 0.1;
            labels[i][0] = Math.max(0.01, Math.min(0.99, truth));
        }

        INDArray featureMatrix = Nd4j.create(features);
        INDArray labelMatrix = Nd4j.create(labels);
        DataSet trainingData = new DataSet(featureMatrix, labelMatrix);

        log.debug("  Training MLP on {} synthetic samples for {} epochs...",
                TRAINING_SAMPLES, TRAINING_EPOCHS);
        for (int epoch = 0; epoch < TRAINING_EPOCHS; epoch++) {
            model.fit(trainingData);
        }

        double score = model.score();
        log.info("  MLP training complete — final loss: {}", String.format("%.6f", score));
    }
}
