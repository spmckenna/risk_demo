import streamlit as st
import os
import pandas as pd


def app():

    hide_table_row_index = """
            <style>
                .row_heading.level0 {display:none}
                .blank {display:none}
            </style>
            """

    st.markdown("### Instructions")

    df = pd.read_csv(os.path.join("inputs", "instructions.csv"), sep=";", names=["Step", "Instruction", "Notes"],
                     index_col=False, header=None)

    st.markdown(hide_table_row_index, unsafe_allow_html=True)
    st.table(df)