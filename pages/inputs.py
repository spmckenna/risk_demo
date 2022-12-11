import os.path
import streamlit as st
import pandas as pd
import numpy as np


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

    st.markdown("### Inputs")

    with st.expander("Organization"):

     #   with st.form(key='basic_form'):
     #       submit_button = st.form_submit_button(label='Update', on_click=update_scores())
     #       st.write('Score for Threat Event Frequency:  ', st.session_state.scores[1])

#        st.markdown("#### Industry")
        with st.container():
            col1, col2 = st.columns(2)
            with col1:
                option1 = st.selectbox(
                    "What NCAIS industry is the targeted organization in?",
                    ("Professional", "Finance", "Manufacturing", "Government", "Retail"), key="question1")
                st.session_state.scores[0]["question1"] = str(option1)
                option2 = st.selectbox(
                    "What is the size (employee count) of the targeted organization?",
                    ("Small", "Large"), key="question2")
                st.session_state.scores[0]["question2"] = str(option2)
                #st.write('Values:', st.session_state.scores[0])
                #s1.update("1", option1)
            #df = pd.read_csv(os.path.join("inputs", "theat_event_freq_1.csv"), sep=";", names=["Value", "Response"],
            #                 index_col=False, header=None)
            #col1, col2 = st.columns(2)
            #with col1:
            #    st.markdown(hide_table_row_index, unsafe_allow_html=True)
            #    st.table(df)

            with col2:
                option3 = st.selectbox(
                    "What geographic region is the targeted organization in?",
                    ("NA", "EMAC", "LAC", "XX"), key="question3")
                st.session_state.scores[0]["question3"] = str(option3)
                #st.write('Values:', st.session_state.scores[0])
                #s1.update("1", option1)
    with st.expander("Attack"):
        #st.markdown("#### Attack")
        with st.container():
            col1, col2 = st.columns(2)
            with col1:
                option1 = st.selectbox(
                    "What is the VERIS Threat Action?",
                    ("Malware", "Hacking", "Social", "Misuse", "Error"), key="question4")
                st.session_state.scores[0]["question4"] = str(option1)
                # st.write('Values:', st.session_state.scores[0])
                # s1.update("1", option1)
            # df = pd.read_csv(os.path.join("inputs", "theat_event_freq_1.csv"), sep=";", names=["Value", "Response"],
            #                 index_col=False, header=None)
            # col1, col2 = st.columns(2)
            # with col1:
            #    st.markdown(hide_table_row_index, unsafe_allow_html=True)
            #    st.table(df)
            option2 = st.selectbox(
                "What is the loss type?",
                ("C", "I", "A"), key="question5")
            st.session_state.scores[0]["question5"] = str(option2)
            with col2:
                option3 = st.selectbox(
                    "What kind of actor is the threat actor?",
                    ("Threat Actor", "Insider", "Third Party"), key="question6")
                st.session_state.scores[0]["question6"] = str(option3)
                # st.write('Values:', st.session_state.scores[0])
                # s1.update("1", option1)

    with st.expander("Threat Actor"):
        #st.markdown("#### Attack")
        with st.container():
            col1, col2 = st.columns(2)
            with col1:
                option1 = st.selectbox(
                    "What is the sophistication of the threat actor?",
                    ("1", "2", "3", "4", "5"), key="question7")
                st.session_state.scores[0]["question7"] = str(option1)

            option2 = st.selectbox(
                "What resources are available to the threat actor?",
                ("1", "2", "3"), key="question8")
            st.session_state.scores[0]["question8"] = str(option2)
            with col2:
                option3 = st.selectbox(
                    "What is the determination of the threat actor?",
                    ("Low", "Medium", "High"), key="question9")
                st.session_state.scores[0]["question9"] = str(option3)
                # st.write('Values:', st.session_state.scores[0])
                # s1.update("1", option1)

    with st.expander("Controls"):
        #st.markdown("#### CSF Control Metrics")
        with st.container():
            col1, col2 = st.columns(2)
            with col1:
                option1 = st.selectbox(
                    "Protect Score",
                    ("1", "2", "3", "4", "5"))
                option2 = st.selectbox(
                    "Respond Score",
                    ("1", "2", "3", "4", "5"))
                option3 = st.selectbox(
                    "Identify Score",
                    ("1", "2", "3", "4", "5"))

            with col2:
                option4 = st.selectbox(
                    "Detect Score",
                    ("1", "2", "3", "4", "5"))
                option5 = st.selectbox(
                    "Recover Score",
                    ("1", "2", "3", "4", "5"))
            # st.write('You selected:', option)

    with st.expander("Impact"):
        #st.markdown("#### Impact $")
        with st.container():
            col1, col2 = st.columns(2)
            with col1:
                option1 = st.selectbox(
                    "Minimum $ loss (x1M)",
                    ("1", "2", "3", "4", "5"))
                option2 = st.selectbox(
                    "Average $ loss (x1M)",
                    ("1", "2", "3", "4", "5"))
                option3 = st.selectbox(
                    "Maximum $ loss (x1M)",
                    ("1", "2", "3", "4", "5"))
            with col2:
                option1 = st.selectbox(
                    "Minimum reputation loss",
                    ("1", "2", "3", "4", "5"))
                option2 = st.selectbox(
                    "Average reputation loss",
                    ("1", "2", "3", "4", "5"))
                option3 = st.selectbox(
                    "Maximum reputation loss",
                    ("1", "2", "3", "4", "5"))

