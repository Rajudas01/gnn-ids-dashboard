import streamlit as st
import pandas as pd

from db import get_upload_history

# =====================================================
# ADMIN PANEL
# =====================================================

def show_admin_panel():

    st.subheader(
        "🛡 Admin Security Center"
    )

    history = get_upload_history()

    if len(history) == 0:

        st.info(
            "No uploads found"
        )

    else:

        df = pd.DataFrame(

            history,

            columns=[

                "Username",

                "Filename",

                "Threat %",

                "Upload Time"
            ]
        )

        # =================================================
        # METRICS
        # =================================================

        c1, c2, c3 = st.columns(3)

        c1.metric(
            "📂 Total Uploads",
            len(df)
        )

        c2.metric(
            "👤 Users",
            df["Username"].nunique()
        )

        c3.metric(
            "🚨 Avg Threat %",
            round(df["Threat %"].mean(), 2)
        )

        st.markdown("---")

        # =================================================
        # HIGH THREAT ALERTS
        # =================================================

        high_threats = df[
            df["Threat %"] > 70
        ]

        if len(high_threats) > 0:

            st.error(
                "🚨 CRITICAL THREATS DETECTED"
            )

            st.dataframe(
                high_threats,
                use_container_width=True
            )

        else:

            st.success(
                "✅ No Critical Threats"
            )

        # =================================================
        # ALL HISTORY
        # =================================================

        st.subheader(
            "📜 Complete Upload Logs"
        )

        st.dataframe(
            df,
            use_container_width=True
        )