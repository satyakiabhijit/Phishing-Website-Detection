## IX. Conclusion

This paper has presented PhishGuard v2, an advanced mathematical feature engineering and stacking ensemble classification framework for phishing URL detection. The principal contributions of this work are threefold.

First, we have identified and systematically addressed the data leakage problem that pervades phishing detection research employing benchmark datasets such as PhiUSIIL. By demonstrating that 29 page-content features encode information unavailable at inference time, and that models trained on these features report artificially perfect accuracy, we have established a rigorous URL-only evaluation methodology that produces honest, deployment-ready performance estimates.

Second, we have developed a principled feature engineering pipeline grounded in information theory, probabilistic language modeling, and computational linguistics. The 21 URL-only features—spanning Shannon entropy, character-class distributions, n-gram perplexity, edit-distance typosquatting detection, obfuscation quantification, and structural decomposition—provide mathematically motivated representations that capture the fundamental statistical differences between legitimate and phishing URLs. The feature importance analysis demonstrates that these features are highly discriminative, with even a simple linear classifier (Logistic Regression) achieving 99.66% accuracy—a strong indicator of feature quality.

Third, we have designed and evaluated a heterogeneous stacking ensemble architecture that combines five diverse base classifiers through a meta-learner that produces calibrated probability outputs. The ensemble achieves 99.79% classification accuracy, 99.90% AUC-ROC, and 99.81% F1-score on a held-out test set of 47,159 URLs, with a false negative rate of only 0.030% (8 missed phishing URLs out of 26,970). These results represent the best reported performance among systems restricted to URL-only features, achieving this with fewer features (21) than most competing approaches.

The practical implications of this work extend beyond academic benchmarking. The framework processes URLs in under 50 milliseconds, enables privacy-preserving classification without page crawling, provides interpretable feature-level explanations for each decision, and establishes a foundation for real-time phishing detection that complements rather than replaces existing blacklist-based defenses.

### Future Research Directions

Several avenues for future work are identified:

1. **Temporal Concept Drift Analysis.** Phishing URL characteristics evolve over time as attackers adapt to detection systems. Longitudinal evaluation of model performance degradation and the development of online learning strategies for continuous model adaptation represent important research directions.

2. **Adversarial Robustness Evaluation.** Systematic adversarial analysis—including gradient-based evasion attacks on the feature space and generative adversarial approaches for phishing URL generation—would provide rigorous bounds on the system's security guarantees under active adversarial pressure.

3. **Cross-Dataset Generalization.** Evaluating the PhishGuard v2 feature set and ensemble architecture on additional phishing URL datasets (e.g., ISCX-URL-2016, Kaggle phishing datasets, OpenPhish) would establish the generalizability of our results beyond the PhiUSIIL distribution.

4. **Feature Space Expansion.** Incorporating WHOIS-derived features (domain age, registrar reputation), passive DNS intelligence (resolution history, IP geolocation), and certificate transparency log analysis could further enhance detection accuracy while maintaining the URL-centric, no-crawling constraint.

5. **Federated Learning.** Distributed model training across organizational boundaries—where each participant contributes locally computed features without sharing raw URLs—would address the privacy and data-sharing barriers that currently limit the scale of phishing detection training data.

---

## References

[1] Anti-Phishing Working Group, "Phishing Activity Trends Report, 4th Quarter 2023," APWG, Tech. Rep., 2024.

[2] Federal Bureau of Investigation, "Internet Crime Report 2022," FBI Internet Crime Complaint Center (IC3), Tech. Rep., 2023.

[3] P. Hannay and G. Baatard, "The 2011 IDN Homograph Attack Mitigation Survey," in *Proc. 10th Australian Information Security Management Conf.*, Perth, Australia, 2012, pp. 13-20.

[4] A. K. Jain and B. B. Gupta, "Phishing Detection: Analysis of Visual Similarity Based Approaches," *Security and Communication Networks*, vol. 2017, pp. 1-20, 2017.

[5] K. Thomas et al., "Data Breaches, Phishing, or Malware? Understanding the Risks of Stolen Credentials," in *Proc. 2017 ACM SIGSAC Conf. on Computer and Communications Security*, 2017, pp. 1421-1434.

[6] S. Sheng, B. Wardman, G. Warner, L. Cranor, J. Hong, and C. Zhang, "An Empirical Analysis of Phishing Blacklists," in *Proc. 6th Conf. on Email and Anti-Spam (CEAS)*, Mountain View, CA, 2009.

[7] T. Moore and R. Clayton, "Examining the Impact of Website Take-down on Phishing," in *Proc. Anti-Phishing Working Group eCrime Researchers Summit*, Pittsburgh, PA, 2007.

[8] Y. Pan and X. Ding, "Anomaly Based Web Phishing Page Detection," in *Proc. 22nd Annual Computer Security Applications Conf. (ACSAC)*, Miami Beach, FL, 2006, pp. 381-392.

[9] R. M. Mohammad, F. Thabtah, and L. McCluskey, "Predicting Phishing Websites Based on Self-Structuring Neural Network," *Neural Computing and Applications*, vol. 25, no. 2, pp. 443-458, 2014.

[10] S. Kaufman, S. Rosset, C. Perlich, and O. Stitelman, "Leakage in Data Mining: Formulation, Detection, and Avoidance," *ACM Transactions on Knowledge Discovery from Data*, vol. 6, no. 4, pp. 1-21, 2012.

[11] N. Provos, P. Mavrommatis, M. A. Rajab, and F. Monrose, "All Your iFRAMEs Point to Us," in *Proc. 17th USENIX Security Symposium*, San Jose, CA, 2008, pp. 1-15.

[12] Microsoft, "Microsoft SmartScreen," 2024. [Online]. Available: https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/

[13] PhishTank, "PhishTank: Join the Fight Against Phishing," 2024. [Online]. Available: https://phishtank.org/

[14] S. Marchal, J. Francois, R. State, and T. Engel, "PhishStorm: Detecting Phishing with Streaming Analytics," *IEEE Transactions on Network and Service Management*, vol. 11, no. 4, pp. 458-471, 2014.

[15] S. Garera, N. Provos, M. Chew, and A. D. Rubin, "A Framework for Detection and Measurement of Phishing Attacks," in *Proc. 2007 ACM Workshop on Recurring Malcode (WORM)*, Alexandria, VA, 2007, pp. 1-8.

[16] Y. Zhang, J. I. Hong, and L. F. Cranor, "CANTINA: A Content-Based Approach to Detecting Phishing Web Sites," in *Proc. 16th International Conf. on World Wide Web (WWW)*, Banff, AB, 2007, pp. 639-648.

[17] G. Xiang, J. Hong, C. P. Rose, and L. Cranor, "CANTINA+: A Feature-Rich Machine Learning Framework for Detecting Phishing Web Sites," *ACM Transactions on Information and System Security*, vol. 14, no. 2, pp. 1-28, 2011.

[18] J. Ma, L. K. Saul, S. Savage, and G. M. Voelker, "Beyond Blacklists: Learning to Detect Malicious Web Sites from Suspicious URLs," in *Proc. 15th ACM SIGKDD Int. Conf. on Knowledge Discovery and Data Mining*, Paris, France, 2009, pp. 1245-1254.

[19] A. Le, A. Markopoulou, and M. Faloutsos, "PhishDef: URL Names Say It All," in *Proc. IEEE INFOCOM*, Shanghai, China, 2011, pp. 191-195.

[20] O. K. Sahingoz, E. Buber, O. Demir, and B. Diri, "Machine Learning Based Phishing Detection from URLs," *Expert Systems with Applications*, vol. 117, pp. 345-357, 2019.

[21] R. S. Rao and A. R. Pais, "Detection of Phishing Websites Using an Efficient Feature-Based Machine Learning Framework," *Neural Computing and Applications*, vol. 31, no. 8, pp. 3851-3873, 2019.

[22] A. C. Bahnsen, E. C. Bohorquez, S. Villegas, J. Vargas, and F. A. Gonzalez, "Classifying Phishing URLs Using Recurrent Neural Networks," in *Proc. APWG Symposium on Electronic Crime Research (eCrime)*, San Diego, CA, 2017, pp. 1-8.

[23] F. Tajaddodianfar, J. W. Stokes, and A. Gururajan, "Texception: A Character/Word-Level Deep Learning Model for Phishing URL Detection," in *Proc. IEEE Int. Conf. on Acoustics, Speech and Signal Processing (ICASSP)*, Brighton, UK, 2020, pp. 2857-2861.

[24] W. Wei, Q. Qin, and Z. Ma, "Phishing Website Detection Based on URL Character-Level BERT," *IEEE Access*, vol. 10, pp. 121414-121425, 2022.

[25] D. Gunning and D. Aha, "DARPA's Explainable Artificial Intelligence (XAI) Program," *AI Magazine*, vol. 40, no. 2, pp. 44-58, 2019.

[26] K. L. Chiew, E. H. Chang, S. N. Sze, and W. K. Tiong, "Utilisation of Website Logo for Phishing Detection," *Computers & Security*, vol. 54, pp. 16-26, 2015.

[27] A. K. Jain and B. B. Gupta, "A Machine Learning Based Approach for Phishing Detection Using Hyperlinks Information," *Journal of Ambient Intelligence and Humanized Computing*, vol. 10, no. 5, pp. 2015-2028, 2019.

[28] D. H. Wolpert, "Stacked Generalization," *Neural Networks*, vol. 5, no. 2, pp. 241-259, 1992.

[29] L. Breiman, "Stacked Regressions," *Machine Learning*, vol. 24, no. 1, pp. 49-64, 1996.

[30] F. T. Liu, K. M. Ting, and Z.-H. Zhou, "Isolation Forest," in *Proc. 8th IEEE Int. Conf. on Data Mining (ICDM)*, Pisa, Italy, 2008, pp. 413-422.

[31] S. Marchal, G. Armano, T. Grondahl, and N. Asokan, "Off-the-Hook: An Efficient and Usable Client-Side Phishing Prevention Application," *IEEE Transactions on Computers*, vol. 66, no. 10, pp. 1717-1733, 2017.

[32] V. Chandola, A. Banerjee, and V. Kumar, "Anomaly Detection: A Survey," *ACM Computing Surveys*, vol. 41, no. 3, pp. 1-58, 2009.

[33] T. Berners-Lee, R. Fielding, and L. Masinter, "Uniform Resource Identifier (URI): Generic Syntax," RFC 3986, Internet Engineering Task Force, 2005.

[34] C. E. Shannon, "A Mathematical Theory of Communication," *The Bell System Technical Journal*, vol. 27, no. 3, pp. 379-423, 1948.

[35] OWASP Foundation, "URL Encoding," OWASP Web Security Testing Guide, 2023.

[36] F. J. Damerau, "A Technique for Computer Detection and Correction of Spelling Errors," *Communications of the ACM*, vol. 7, no. 3, pp. 171-176, 1964.

[37] L. Breiman, "Random Forests," *Machine Learning*, vol. 45, no. 1, pp. 5-32, 2001.

[38] T. Chen and C. Guestrin, "XGBoost: A Scalable Tree Boosting System," in *Proc. 22nd ACM SIGKDD Int. Conf. on Knowledge Discovery and Data Mining*, San Francisco, CA, 2016, pp. 785-794.

[39] G. Ke et al., "LightGBM: A Highly Efficient Gradient Boosting Decision Tree," in *Proc. 31st Int. Conf. on Neural Information Processing Systems (NeurIPS)*, Long Beach, CA, 2017, pp. 3146-3154.

[40] D. P. Kingma and J. Ba, "Adam: A Method for Stochastic Optimization," in *Proc. 3rd Int. Conf. on Learning Representations (ICLR)*, San Diego, CA, 2015.

[41] R. Prasad, "PhiUSIIL Phishing URL Dataset," UCI Machine Learning Repository, 2024. [Online]. Available: https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset

[42] A. P. Bradley, "The Use of the Area Under the ROC Curve in the Evaluation of Machine Learning Algorithms," *Pattern Recognition*, vol. 30, no. 7, pp. 1145-1159, 1997.

[43] R. Caruana, A. Niculescu-Mizil, G. Crew, and A. Ksikes, "Ensemble Selection from Libraries of Models," in *Proc. 21st International Conf. on Machine Learning (ICML)*, Banff, AB, 2004, pp. 18-25.

[44] N. V. Chawla, K. W. Bowyer, L. O. Hall, and W. P. Kegelmeyer, "SMOTE: Synthetic Minority Over-Sampling Technique," *Journal of Artificial Intelligence Research*, vol. 16, pp. 321-357, 2002.

[45] S. Abu-Nimeh, D. Nappa, X. Wang, and S. Nair, "A Comparison of Machine Learning Techniques for Phishing Detection," in *Proc. Anti-Phishing Working Group eCrime Researchers Summit*, Pittsburgh, PA, 2007, pp. 60-69.

---

*Manuscript submitted for review. All experimental results were generated from the PhishGuard v2 repository at https://github.com/satyakiabhijit/Phishing-Website-Detection.*
