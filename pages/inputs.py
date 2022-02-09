import os.path

import streamlit as st
import pandas as pd
import numpy as np
import os


class Scores():
    def __init__(self):
        self.options = {"1": 1, "2": 1}
        self.update("1", 1)
        self.update("2", 1)
        self.score = 0.

    def update(self, option, value):
        self.options[option] = value
        a = sum([float(v) for k, v in self.options.items()])
        b = sum([1.0 for k in self.options.keys()])

        self.score = a / b


def update_scores():
    a = np.sum([float(v) for k, v in st.session_state.scores[0].items()])
    b = 2 # np.sum([1.0 for k in st.session_state.scores[0].keys()])
    st.session_state.scores[1] = a / b
    #st.write('Values:', st.session_state.scores[0])
    #st.write('Score:', st.session_state.scores[1])
    #st.write('a:', a)


def app():

    # set variables in session state
#    st.session_state.scores = Scores()
    st.session_state.scores = [{"question1": 1, "question2": 1}, 1]

    hide_table_row_index = """
            <style>
                .row_heading.level0 {display:none}
                .blank {display:none}
            </style>
            """
#    s1 = Scores()

    with st.expander("Analysis - Threat Event Frequency"):

     #   with st.form(key='basic_form'):
     #       submit_button = st.form_submit_button(label='Update', on_click=update_scores())
     #       st.write('Score for Threat Event Frequency:  ', st.session_state.scores[1])


        st.markdown("#### Contact Frequency")
        with st.container():
            df = pd.read_csv(os.path.join("inputs", "theat_event_freq_1.csv"), sep=";", names=["Value", "Response"],
                             index_col=False, header=None)
            col1, col2 = st.columns(2)
            with col1:
                st.markdown(hide_table_row_index, unsafe_allow_html=True)
                st.table(df)

            with col2:
                option1 = st.selectbox(
                    "Using the scale to the left, what resources and opportunities are required in order to come into contact with the asset?",
                    ("1", "2", "3", "4", "5"), key="question1")
                st.session_state.scores[0]["question1"] = float(option1)
                #st.write('Values:', st.session_state.scores[0])
                #s1.update("1", option1)

        st.markdown("#### Probability of Action")
        with st.container():
            df = pd.read_csv(os.path.join("inputs", "theat_event_freq_1.csv"), sep=";", names=["Value", "Response"],
                             index_col=False, header=None)
            col1, col2 = st.columns(2)
            with col1:
                st.markdown(hide_table_row_index, unsafe_allow_html=True)
                st.table(df)

            with col2:
                option2 = st.selectbox(
                    "Using the scale to the left, how motivated is the threat actor to accomplish its objective?",
                    ("1", "2", "3", "4", "5"), key="question2")
                st.session_state.scores[0]["question2"] = float(option2)
                #st.write('Values:', st.session_state.scores[0])
                #s1.update("2", option2)
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
