# Model card

The active live detector is a rule comparing observed origin to the configured lab-only authorization baseline. The copied Random Forest artifact was trained on synthetic data where origin mismatch directly encoded the target; it is not used by the API and is not evidence of generalization. A guarded historical training and evaluation command exists, but no eligible real-data model has been trained or evaluated. Anomaly scores are not displayed as calibrated probabilities.
