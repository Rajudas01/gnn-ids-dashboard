import shap
import pandas as pd
import matplotlib.pyplot as plt

def generate_shap_explanation(
    model,
    x_tensor,
    feature_names
):

    try:

        # CONVERT TO NUMPY
        x_np = x_tensor.numpy()

        # SIMPLE EXPLAINER
        explainer = shap.Explainer(

            lambda data: model(
                x_tensor,
                None
            ).detach().numpy(),

            x_np
        )

        shap_values = explainer(x_np)

        # PLOT
        fig, ax = plt.subplots()

        shap.plots.bar(
            shap_values,
            show=False
        )

        return fig

    except Exception as e:

        return None