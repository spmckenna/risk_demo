import streamlit as st
import datetime


def app():
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### Setup")

        scenario_id = st.text_input('Scenario ID', 'Risk Scenario #X')
        scenario_description = st.text_input('Scenario Description', '')
        asset = st.text_input('Asset', '')
        assessment_date = st.date_input("Assessment Date", datetime.date.today())
        notes = st.text_input('Notes', '')

