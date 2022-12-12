import streamlit as st
import pandas as pd
import networkx as nx
import os
from model.model.VistaInput import VistaInput, AttackMotivators, AttackSurface, Exploitability, ThreatActorInput, \
    quantImpact, CsfFunction, CsfIdentify, IDAM, CsfProtect, IDBE, IDGV, IDSC, IDRM, IDRA, PRAC, PRAT, \
    PRDS, PRIP, PRMA, PRPT, CsfDetect, DEAE, DECM, DEDP, CsfRespond, RSRP, RSCO, RSAN, RSMI, RSIM, CsfRecover, RCCO, \
    RCIM, RCRP
from model.model.run_vista import runVista
from model.model.scenario_module.ScenarioModel import Scenario
from htbuilder import div, big, h2, styles
from htbuilder.units import rem
import datetime
import matplotlib.pyplot as plt
from math import pi


def local_css(file_name):
    with open(file_name) as f:
        st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)


def display_dial(title, value, color):
    st.markdown(
        div(
            style=styles(
                text_align="center",
                color=color,
                padding=(rem(0.8), 0, rem(3), 0),
            )
        )(
            h2(style=styles(font_size=rem(0.8), font_weight=600, padding=0))(title),
            big(style=styles(font_size=rem(3), font_weight=800, line_height=1))(
                value
            ),
        ),
        unsafe_allow_html=True,
    )


local_css(os.path.join(os.path.dirname(__file__), "style.css"))
st.header("Simulation of Probabilistic Risk (SuPeR)")
st.write("Powered by Cyber Risk Computational Engine (CyRCE) ver. beta.12.11.12")
with st.container():
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### Scenario")

        scenario_id = st.text_input('Scenario ID', 'Risk Scenario #X')
        scenario_description = st.text_input('Scenario Description', '')
        assessment_date = st.date_input("Date", datetime.date.today())
        notes = st.text_input('Notes', '')

    with col2:
        st.markdown("### Inputs")

        with st.expander("Organization"):
            industry = st.selectbox(
                "What NCAIS industry is the targeted organization in?",
                ("Accommodation",
                 "Administrative",
                 "Construction",
                 "Education",
                 "Entertainment",
                 "Finance",
                 "Health Care",
                 "Information",
                 "Manufacturing",
                 "Mining and Utilities",
                 "Other Services",
                 "Professional",
                 "Public Administration",
                 "Real Estate",
                 "Retail",
                 "Transportation"), key="industry", index=0)
            size = st.selectbox(
                "What is the size (employee count) of the targeted organization?",
                ("Small", "Large"), key="size", index=1)
            region = st.selectbox(
                "What geographic region is the targeted organization in?",
                ("NA", "EMAC", "LAC", "APAC", "Global"), key="region", index=0)

        with st.expander("Attack"):
            action = st.selectbox(
                "What is the VERIS Threat Action?",
                ("Malware", "Hacking", "Social", "Misuse", "Error"), key="action", index=1)
            loss = st.selectbox(
                "What is the loss type?",
                ("C", "I", "A"), key="loss", index=0)
            actor = st.selectbox(
                "What kind of actor is the threat actor?",
                ("Threat Actor", "Insider", "Third Party"), key="actor", index=0)

        with st.expander("Threat Actor"):
            sophistication = st.selectbox(
                "What is the sophistication of the threat actor?",
                ('None', 'Minimal', 'Intermediate', 'Advanced', 'Expert', 'Innovator', 'Strategic'),
                key="sophistication", index=4)
            resources = st.selectbox(
                "What resources are available to the threat actor?",
                ('Individual', 'Club', 'Contest', 'Team', 'Organization', 'Government'), key="resources", index=4)
            determination = st.selectbox(
                "What is the determination of the threat actor?",
                ("Low", "Medium", "High"), key="determination", index=2)

        with st.expander("Controls"):
            identifyScore = 0.25 * (float(st.selectbox(
                "Identify Score",
                ("1", "2", "3", "4", "5"), key="identifyScore", index=2)) - 1)
            protectScore = 0.25 * (float(st.selectbox(
                "Protect Score",
                ("1", "2", "3", "4", "5"), key="protectScore", index=2)) - 1)
            detectScore = 0.25 * (float(st.selectbox(
                "Detect Score",
                ("1", "2", "3", "4", "5"), key="detectScore", index=2)) - 1)
            respondScore = 0.25 * (float(st.selectbox(
                "Respond Score",
                ("1", "2", "3", "4", "5"), key="respondScore", index=2)) - 1)
            recoverScore = 0.25 * (float(st.selectbox(
                "Recover Score",
                ("1", "2", "3", "4", "5"), key="recoverScore", index=2)) - 1)

        with st.expander("Impact"):
            minDollars = st.text_input('Minimum $ loss (x $1M)', '1', key="minDollars")
            avgDollars = st.text_input('Mean $ loss (x $1M)', '3', key="avgDollars")
            maxDollars = st.text_input('Maximum $ loss (x $1M)', '10', key="maxDollars")

    st.markdown("### Compute")

    graph = nx.read_graphml(os.path.join(os.path.dirname(__file__),
                                         'model/model/resources/vista_enterprise_network_model.graphml'))

    attackMotivators = AttackMotivators(2, 3, 2, 3)
    attackSurface = AttackSurface(2, 3)
    exploitability = Exploitability(2.5)
    threatActorInput = ThreatActorInput(determination=determination.lower(), resources=resources.lower(),
                                        sophistication=sophistication.lower())
    # directImpact = DirectImpact(3, float(maxDollars), float(averageDollars), float(minDollars))
    # indirectImpact = IndirectImpact(3, float(maxRep), float(averageRep), float(minRep))
    # impact = Impact(directImpact, indirectImpact)
    quantImpact = quantImpact(float(minDollars), float(avgDollars), float(maxDollars))

    scenario = Scenario(attackAction=action.lower(), attackThreatType=actor.lower().replace(" ", ""),
                        attackTarget='enterprise',
                        attackLossType=loss.lower(), attackIndustry=industry.lower().replace(" ", ""),
                        attackGeography=region.lower(), orgSize=size.lower())
    # scenario = Scenario()
    identify = CsfIdentify(IDAM=IDAM(0.8, 0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
                           IDBE=IDBE(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
                           IDGV=IDGV(0.8, 0.8, 0.8, 0.8, 0.8),
                           IDRA=IDRA(0.8, 0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
                           IDRM=IDRM(0.8, 0.8, 0.8, 0.8),
                           IDSC=IDSC(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
                           value=identifyScore)
    protect = CsfProtect(value=protectScore,
                         PRAC=PRAC(value=0.4, PRAC1=0.4, PRAC2=0.4, PRAC3=0.4, PRAC4=0.4, PRAC5=0.4,
                                   PRAC6=0.4,
                                   PRAC7=0.4),
                         PRAT=PRAT(value=0.4, PRAT1=0.4, PRAT2=0.4, PRAT3=0.4, PRAT4=0.4, PRAT5=0.4),
                         PRDS=PRDS(value=0.4, PRDS1=0.4, PRDS2=0.4, PRDS3=0.4, PRDS4=0.4, PRDS5=0.4,
                                   PRDS6=0.4,
                                   PRDS7=0.4, PRDS8=0.4),
                         PRIP=PRIP(value=0.4, PRIP1=0.4, PRIP2=0.4, PRIP3=0.4, PRIP4=0.4, PRIP5=0.4,
                                   PRIP6=0.4,
                                   PRIP7=0.4, PRIP8=0.4,
                                   PRIP9=0.4, PRIP10=0.4, PRIP11=0.4, PRIP12=0.4),
                         PRMA=PRMA(value=0.4, PRMA1=0.4, PRMA2=0.4),
                         PRPT=PRPT(value=0.4, PRPT1=0.4, PRPT2=0.4, PRPT3=0.4, PRPT4=0.4, PRPT5=0.4))
    detect = CsfDetect(value=detectScore,
                       DEAE=DEAE(value=0.4, DEAE1=0.4, DEAE2=0.4, DEAE3=0.4, DEAE4=0.4, DEAE5=0.4),
                       DECM=DECM(value=0.4, DECM1=0.4, DECM2=0.4, DECM3=0.4, DECM4=0.4, DECM5=0.4,
                                 DECM6=0.4,
                                 DECM7=0.4,
                                 DECM8=0.4),
                       DEDP=DEDP(value=0.4, DEDP1=0.4, DEDP2=0.4, DEDP3=0.4, DEDP4=0.4, DEDP5=0.4))
    respond = CsfRespond(value=respondScore,
                         RSRP=RSRP(value=0.426, RSRP1=0.426),
                         RSCO=RSCO(value=0.426, RSCO1=0.426, RSCO2=0.426, RSCO3=0.426, RSCO4=0.426,
                                   RSCO5=0.426),
                         RSAN=RSAN(value=0.426, RSAN1=0.426, RSAN2=0.426, RSAN3=0.426, RSAN4=0.426,
                                   RSAN5=0.426),
                         RSMI=RSMI(value=0.426, RSMI1=0.426, RSMI2=0.426, RSMI3=0.426),
                         RSIM=RSIM(value=0.426, RSIM1=0.426, RSIM2=0.426))
    recover = CsfRecover(value=recoverScore,
                         RCRP=RCRP(value=0.426, RCRP1=0.426),
                         RCIM=RCIM(value=0.426, RCIM1=0.426, RCIM2=0.426),
                         RCCO=RCCO(value=0.426, RCCO1=0.426, RCCO2=0.426, RCCO3=0.426))
    csf = CsfFunction(identify=identify,
                      protect=protect,
                      detect=detect,
                      respond=respond,
                      recover=recover)

    vista_input = VistaInput(attackMotivators=attackMotivators,
                             attackSurface=attackSurface,
                             exploitability=exploitability,
                             threatActorInput=threatActorInput,
                             quantImpact=quantImpact,
                             csf=csf,
                             scenario=scenario,
                             mitreControls=[])

    with st.form(key="my_form"):
        pressed = st.form_submit_button("Go!")
        prog_bar = st.progress(0)
        run = False

with st.container():
    if pressed:
        stop = False
        if float(avgDollars) <= float(minDollars):
            st.error('Average impact must be >= minimum impact')
            stop = True
        elif float(maxDollars) <= float(avgDollars):
            st.error('Maximum impact must be >= average impact')
            stop = True
        if not stop:
            st.markdown("### Results")
            # with st.spinner('Wait for it ...'):
            # with st.container():
            #prog_bar = st.progress(0)
            vista_output = runVista(vista_input, graph, prog_bar)
            run = True

    if run:

        lossDict = {'c': 'Confidentiality',
                    'i': 'Integrity',
                    'a': 'Availability'}
        st.write("###", action, "by ", actor, "causing loss of ", lossDict[loss.lower()])
        st.write(
            "Assuming the scenario occurs, these results quantify the likelihood of, and the loss due to, a successful attack.")
        st.write(
            "The Risk Level combines these two elements into a single risk score - higher scores mean higher risk.")

        COLOR_RED = "#FF4B4B"
        COLOR_BLUE = "#1C83E1"
        COLOR_CYAN = "#00C0F2"
        COLOR_YELLOW = "#FFC300"

        if vista_output.overallResidualRiskLevel.value > 4:
            risk_color = COLOR_RED
        elif vista_output.overallResidualRiskLevel.value > 2.5:
            risk_color = COLOR_YELLOW
        else:
            risk_color = COLOR_BLUE

        if vista_output.overallResidualLikelihood.value > .2:
            lh_color = COLOR_RED
        elif vista_output.overallResidualLikelihood.value > .1:
            lh_color = COLOR_YELLOW
        else:
            lh_color = COLOR_BLUE

        if vista_output.overallResidualImpact.value > float(avgDollars):
            imp_color = COLOR_RED
        elif vista_output.overallResidualImpact.value > (float(avgDollars) + float(minDollars)) / 2:
            imp_color = COLOR_YELLOW
        else:
            imp_color = COLOR_BLUE

        subjectivity_color = COLOR_CYAN

        a, b, c = st.columns(3)

        with a:
            display_dial("Risk Level", f"{round(vista_output.overallResidualRiskLevel.value, 2)}", risk_color)
        with b:
            display_dial(
                "Likelihood", f"{round(100 * vista_output.overallResidualLikelihood.value, 0)}%", lh_color
            )
        with c:
            display_dial(
                "Impact", f"${round(vista_output.overallResidualImpact.value, 2)}M", imp_color
            )

        prog_bar.empty()
        run = False

        st.markdown("#### Export")
        st.write("Notional only at this point.")


        @st.cache
        def convert_df(df):
            # IMPORTANT: Cache the conversion to prevent computation on every rerun
            return df.to_csv().encode('utf-8')


        df = pd.DataFrame({
            'protect': [protectScore],
            'detect': [detectScore],
            'respond': [respondScore],
            'recover': [recoverScore]
        })

        csv = convert_df(df)

        st.download_button(
            label="Download to CSV",
            data=csv,
            file_name='risk_results.csv',
            mime='text/csv',
        )
