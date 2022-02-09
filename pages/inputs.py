import os.path

import streamlit as st
import pandas as pd
import numpy as np
import os


def app():
    hide_table_row_index = """
            <style>
                .row_heading.level0 {display:none}
                .blank {display:none}
            </style>
            """

    with st.expander("Analysis - Threat Event Frequency"):
        st.markdown("#### Contact Frequency")
        with st.container():
            df = pd.read_csv(os.path.join("inputs", "theat_event_freq_1.csv"), sep=";", names=["Value", "Response"],
                             index_col=False, header=None)
            col1, col2 = st.columns(2)
            with col1:
                st.markdown(hide_table_row_index, unsafe_allow_html=True)
                st.table(df)

            with col2:
                option = st.selectbox(
                    "Using the scale to the left, what resources and opportunities are required in order to come into contact with the asset?",
                    ("1", "2", "3", "4", "5"))
                # st.write('You selected:', option)

        st.markdown("#### Probability of Action")
        with st.container():
            df = pd.read_csv(os.path.join("inputs", "theat_event_freq_1.csv"), sep=";", names=["Value", "Response"],
                             index_col=False, header=None)
            col1, col2 = st.columns(2)
            with col1:
                st.markdown(hide_table_row_index, unsafe_allow_html=True)
                st.table(df)

            with col2:
                option = st.selectbox(
                    "Using the scale to the left, how motivated is the threat actor to accomplish its objective?",
                    ("1", "2", "3", "4", "5"))
                # st.write('You selected:', option)

    with st.expander("Analysis - Threat Capability"):
        st.markdown("#### Threat Capability")
        with st.container():
            df = pd.read_csv(os.path.join("inputs", "theat_event_freq_1.csv"), sep=";", names=["Value", "Response"],
                             index_col=False, header=None)
            col1, col2 = st.columns(2)
            with col1:
                st.markdown(hide_table_row_index, unsafe_allow_html=True)
                st.table(df)

            with col2:
                option = st.selectbox(
                    "Using the categories to the left, which motivation level below is most representative of the actor in the scenario?",
                    ("1", "2", "3", "4", "5"))
            # st.write('You selected:', option)

    with st.expander("Analysis - Control Strength"):
        st.markdown("#### Control Strength")
        with st.container():
            df = pd.read_csv(os.path.join("inputs", "theat_event_freq_1.csv"), sep=";", names=["Value", "Response"],
                             index_col=False, header=None)
            col1, col2 = st.columns(2)
            with col1:
                st.markdown(hide_table_row_index, unsafe_allow_html=True)
                st.table(df)

            with col2:
                option = st.selectbox(
                    "Using ?",
                    ("1", "2", "3", "4", "5"))
            # st.write('You selected:', option)

    with st.expander("Analysis - Impact"):
        st.markdown("#### Threat Capability")
        with st.container():
            df = pd.read_csv(os.path.join("inputs", "theat_event_freq_1.csv"), sep=";", names=["Value", "Response"],
                             index_col=False, header=None)
            col1, col2 = st.columns(2)
            with col1:
                st.markdown(hide_table_row_index, unsafe_allow_html=True)
                st.table(df)

            with col2:
                option = st.selectbox(
                    "Using the ?",
                    ("1", "2", "3", "4", "5"))
            # st.write('You selected:', option)
