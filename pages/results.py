import streamlit as st
import plotly.figure_factory as ff
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from math import pi
from PIL import Image


def app():

    st.markdown("### Results (fake)")
    image = Image.open('model.png')

    with st.spinner('Wait for it ...'):

        col1, col2 = st.columns(2)
        with col1:
            # Set data
            df = pd.DataFrame({
                'group': ['A', 'B', 'C', 'D'],
                'frequency': [38, 1.5, 30, 4],
                'vulnerability': [29, 10, 9, 34],
                'primary loss': [8, 39, 23, 24],
                'secondary risk': [7, 31, 33, 14]
            })

            # number of variable
            categories = list(df)[1:]
            N = len(categories)

            # We are going to plot the first line of the data frame.
            # But we need to repeat the first value to close the circular graph:
            values = df.loc[0].drop('group').values.flatten().tolist()
            values += values[:1]

            # What will be the angle of each axis in the plot? (we divide the plot / number of variable)
            angles = [n / float(N) * 2 * pi for n in range(N)]
            angles += angles[:1]

            # Initialise the spider plot
            fig = plt.figure()
            ax = plt.subplot(121, polar=True)

            # Draw one axe per variable + add labels
            plt.xticks(angles[:-1], categories, color='grey', size=8)

            # Draw ylabels
            ax.set_rlabel_position(0)
            plt.yticks([10, 20, 30], ["10", "20", "30"], color="grey", size=7)
            plt.ylim(0, 40)

            # Plot data
            ax.plot(angles, values, linewidth=1, linestyle='solid')

            # Fill area
            ax.fill(angles, values, 'b', alpha=0.1)

            st.pyplot(fig)
            # df = pd.DataFrame(dict(
            #     r=[1, 5, 2, 3],
            #     theta=['frequency', 'vulnerability', 'primary loss', 'secondary risk']))
            # fig = px.line_polar(df, r='r', theta='theta', line_close=True)
            # fig.update_traces(fill='toself')
            # st.plotly_chart(fig, use_container_width=True)

        with col2:

            st.image(image, caption='Risk Model')

            # Add histogram data
            x1 = np.random.randn(200) - 2
            x2 = np.random.randn(200)
            x3 = np.random.randn(200) + 2

            # Group data together
            hist_data = [x1, x2, x3]

            group_labels = ['Likelihood', 'Impact', 'Risk']

            # Create distplot with custom bin_size
            fig = ff.create_distplot(
                hist_data, group_labels, bin_size=[.1, .25, .5])

            # Plot!
            st.plotly_chart(fig, use_container_width=True)



        # # Set data
        # df = pd.DataFrame({
        #     'group': ['A', 'B', 'C', 'D'],
        #     'var1': [38, 1.5, 30, 4],
        #     'var2': [29, 10, 9, 34],
        #     'var3': [8, 39, 23, 24],
        #     'var4': [7, 31, 33, 14],
        #     'var5': [28, 15, 32, 14]
        # })
        #
        # # number of variable
        # categories = list(df)[1:]
        # N = len(categories)
        #
        # # We are going to plot the first line of the data frame.
        # # But we need to repeat the first value to close the circular graph:
        # values = df.loc[0].drop('group').values.flatten().tolist()
        # values += values[:1]
        #
        # # What will be the angle of each axis in the plot? (we divide the plot / number of variable)
        # angles = [n / float(N) * 2 * pi for n in range(N)]
        # angles += angles[:1]
        #
        # # Initialise the spider plot
        # fig = plt.figure()
        # ax = plt.subplot(111, polar=True)
        #
        # # Draw one axe per variable + add labels
        # plt.xticks(angles[:-1], categories, color='grey', size=8)
        #
        # # Draw ylabels
        # ax.set_rlabel_position(0)
        # plt.yticks([10, 20, 30], ["10", "20", "30"], color="grey", size=7)
        # plt.ylim(0, 40)
        #
        # # Plot data
        # ax.plot(angles, values, linewidth=1, linestyle='solid')
        #
        # # Fill area
        # ax.fill(angles, values, 'b', alpha=0.1)
        #
        # st.pyplot(fig)