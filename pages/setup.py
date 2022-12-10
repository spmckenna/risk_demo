import streamlit as st
import datetime
import pandas as pd


def app():
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### Setup")

        scenario_id = st.text_input('Scenario ID', 'Risk Scenario #X')
        scenario_description = st.text_input('Scenario Description', '')
        asset = st.text_input('Asset', '')
        assessment_date = st.date_input("Assessment Date", datetime.date.today())
        notes = st.text_input('Notes', '')

    with col2:
        st.markdown("### Compute")
        with st.form(key="my_form"):
            pressed = st.form_submit_button("Go")

        st.markdown("### Export")

        @st.cache
        def convert_df(df):
            # IMPORTANT: Cache the conversion to prevent computation on every rerun
            return df.to_csv().encode('utf-8')

        df = pd.DataFrame({
            'group': ['A', 'B', 'C', 'D'],
            'frequency': [38, 1.5, 30, 4],
            'vulnerability': [29, 10, 9, 34],
            'primary loss': [8, 39, 23, 24],
            'secondary risk': [7, 31, 33, 14]
        })

        csv = convert_df(df)

        st.download_button(
            label="Download to CSV",
            data=csv,
            file_name='vista.csv',
            mime='text/csv',
        )
