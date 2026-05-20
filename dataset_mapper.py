COLUMN_MAPPING = {

    "Duration": "Flow Duration",

    "Forward Packets": "Total Fwd Packets",

    "Backward Packets": "Total Backward Packets",

    "Bytes/s": "Flow Bytes/s",

    "Packets/s": "Flow Packets/s",

    "Pkt Len Mean": "Packet Length Mean",

    "Pkt Len Std": "Packet Length Std",

    "SYN Count": "SYN Flag Count",

    "ACK Count": "ACK Flag Count",

    "Avg Packet Size": "Average Packet Size"
}

# =====================================================
# AUTO MAP DATASET COLUMNS
# =====================================================

def auto_map_columns(df):

    for old_col, new_col in COLUMN_MAPPING.items():

        if old_col in df.columns:

            df.rename(

                columns={
                    old_col: new_col
                },

                inplace=True
            )

    return df