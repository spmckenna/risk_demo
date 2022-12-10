import streamlit as st

#https://towardsdatascience.com/creating-multipage-applications-using-streamlit-efficiently-b58a58134030

# Custom imports
from multipage import MultiPage
from pages import setup, instructions, inputs, results

# Create an instance of the app
app = MultiPage()

# Title of the main page
st.set_page_config(layout="wide")
st.title("Cyber Risk Platform (CRiPto)")

# Add all your applications (pages) here
app.add_page("Setup", setup.app)
app.add_page("Inputs", inputs.app)
app.add_page("Results", results.app)
app.add_page("Instructions", instructions.app)

# The main app
app.run()
