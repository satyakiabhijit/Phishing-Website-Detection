#!/usr/bin/env python3
import streamlit as st
import pandas as pd
import os
import sys

# Add the current directory to the path to import AdvancedPhishingDetector from training.py
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# --- Streamlit UI Configuration ---
# st.set_page_config() MUST be the first Streamlit command
st.set_page_config(
    page_title="Advanced Phishing URL Detector",
    layout="wide",  # Use wide layout for more space
    initial_sidebar_state="collapsed", # Can be 'auto', 'expanded', 'collapsed'
    page_icon="🛡️" # Added a shield emoji as page icon
)

# Custom CSS for better aesthetics - DARK COLOR PALETTE
st.markdown("""
<style>
    /* Import Google Font - Roboto is a good, clean choice */
    @import url('https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;700&display=swap');

    html, body, [class*="st-"] {
        font-family: 'Roboto', sans-serif;
    }

    .reportview-container .main .block-container{
        padding-top: 2rem;
        padding-right: 3rem; /* Slightly more horizontal padding */
        padding-left: 3rem;
        padding-bottom: 2rem;
    }
    .stButton>button {
        width: 100%;
        border-radius: 0.75rem; /* Slightly more rounded */
        font-size: 1.15rem; /* Slightly larger font */
        padding: 0.9rem 0; /* Slightly more padding */
        margin-top: 1.2rem; /* More space above button */
        box-shadow: 0 5px 12px rgba(0, 0, 0, 0.3); /* More prominent shadow for dark theme */
        transition: all 0.3s ease;
        /* Dark Theme Button Gradient: vibrant blue */
        background-image: linear-gradient(to right, #007bff 0%, #0056b3  100%);
        color: white;
        border: none;
        font-weight: 700; /* Bold font for buttons */
        letter-spacing: 0.05em; /* A little letter spacing */
    }
    .stButton>button:hover {
        transform: translateY(-3px); /* More pronounced lift on hover */
        box-shadow: 0 8px 15px rgba(0, 0, 0, 0.4); /* Stronger shadow on hover */
        /* Dark Theme Button Hover Gradient */
        background-image: linear-gradient(to right, #0056b3 0%, #007bff  100%);
    }
    .stTextInput>div>div>input {
        border-radius: 0.75rem; /* Match button curvature */
        padding: 0.85rem 1.2rem; /* More padding */
        font-size: 1.05rem;
        /* Dark Theme Input Colors */
        background-color: #212529; /* Darker input background */
        color: #f8f9fa; /* Light text for input */
        border: 1px solid #495057; /* Muted border */
        box-shadow: inset 0 1px 3px rgba(0,0,0,0.2); /* Inner shadow for depth */
        transition: border-color 0.3s ease, box-shadow 0.3s ease;
    }
    .stTextInput>div>div>input:focus {
        /* Highlight on focus - Updated to match new primary color */
        border-color: #007bff;
        box-shadow: 0 0 0 0.2rem rgba(0, 123, 255, 0.25); /* Focus ring */
        outline: none; /* Remove default outline */
    }
    h1 {
        /* Updated H1 color for dark theme: vibrant blue */
        color: #00BFFF; /* A bright sky blue for main title */
        text-align: center;
        font-size: 3.5em;
        margin-bottom: 0.6em;
        text-shadow: 2px 2px 6px rgba(0,0,0,0.3); /* More prominent text shadow */
        font-weight: 700;
    }
    h2, h3, h4 {
        /* Updated H2, H3, H4 color for dark theme: a slightly muted blue */
        color: #6C757D; /* Muted grey-blue for subtitles */
        border-bottom: 2px solid #343a40; /* Darker border for dark theme */
        padding-bottom: 0.6rem;
        margin-top: 2rem;
        font-weight: 700;
    }
    .stAlert {
        border-radius: 0.75rem;
        font-weight: bold;
        margin-top: 1rem;
        margin-bottom: 1rem;
    }
    .stInfo {
        /* Dark Theme Info Colors */
        background-color: #1a2c3a; /* Dark blue background */
        color: #87CEEB; /* Lighter blue text */
        border-left: 6px solid #17A2B8; /* Teal border */
        border-radius: 0.75rem;
        padding: 1.2rem;
        margin-bottom: 0.75rem;
        box-shadow: 0 2px 5px rgba(0,0,0,0.2);
    }
    .stSuccess {
        /* Dark Theme Success Colors */
        background-color: #1f3320; /* Dark green background */
        color: #90EE90; /* Light green text */
        border-left: 6px solid #28A745; /* Green border */
        border-radius: 0.75rem;
        padding: 1.2rem;
        margin-bottom: 0.75rem;
        box-shadow: 0 2px 5px rgba(0,0,0,0.2);
    }
    .stError {
        /* Dark Theme Error Colors */
        background-color: #341e1e; /* Dark red background */
        color: #FA8072; /* Light red text */
        border-left: 6px solid #DC3545; /* Strong red border */
        border-radius: 0.75rem;
        padding: 1.2rem;
        margin-bottom: 0.75rem;
        box-shadow: 0 2px 5px rgba(0,0,0,0.2);
    }
    .stWarning {
        /* Dark Theme Warning Colors */
        background-color: #3a321e; /* Dark yellow background */
        color: #FFD700; /* Gold text */
        border-left: 6px solid #FFC107; /* Orange-yellow border */
        border-radius: 0.75rem;
        padding: 1.2rem;
        margin-bottom: 0.75rem;
        box-shadow: 0 2px 5px rgba(0,0,0,0.2);
    }
    .phishing-prediction {
        /* Dark Theme Phishing Prediction Colors */
        background-color: #341e1e; /* Darker red background */
        border-left: 10px solid #DC3545; /* Strong red border */
        padding: 1.8rem;
        border-radius: 1rem;
        margin-bottom: 1.8rem;
        box-shadow: 0 6px 15px rgba(220, 53, 69, 0.4); /* Stronger shadow with new red */
        text-align: center;
    }
    .legitimate-prediction {
        /* Dark Theme Legitimate Prediction Colors */
        background-color: #1f3320; /* Darker green background */
        border-left: 10px solid #28A745; /* Green border */
        padding: 1.8rem;
        border-radius: 1rem;
        margin-bottom: 1.8rem;
        box-shadow: 0 6px 15px rgba(40, 167, 69, 0.4);
        text-align: center;
    }
    .phishing-prediction h3, .legitimate-prediction h3 {
        margin: 0;
        font-size: 2.2em;
        color: #f8f9fa; /* Light text for prediction */
    }
    .phishing-prediction h3 span {
        color: #FA8072; /* Lighter red for text inside phishing prediction */
    }
    .legitimate-prediction h3 span {
        color: #90EE90; /* Lighter green for text inside legitimate prediction */
    }

    /* Metric styling for dark theme */
    div[data-testid="stMetric"] {
        background-color: #212529; /* Dark grey background for metrics */
        border-radius: 0.75rem;
        padding: 1.2rem;
        box-shadow: 0 3px 8px rgba(0,0,0,0.25); /* More defined shadow */
        text-align: center;
        margin-bottom: 1rem;
    }
    div[data-testid="stMetricLabel"] {
        font-size: 1em;
        color: #adb5bd; /* Muted light grey */
        font-weight: 500;
        text-transform: uppercase;
        letter-spacing: 0.03em;
    }
    div[data-testid="stMetricValue"] {
        font-size: 2em;
        font-weight: 700;
        color: #e9ecef; /* Very light grey */
        margin-top: 0.3em;
    }
    /* Overall app background for dark theme */
    .stApp {
        background: linear-gradient(to bottom right, #121212, #212121); /* Dark gradient */
        color: #f8f9fa; /* Default text color for the app */
    }
    p {
        color: #e9ecef; /* Ensures general paragraph text is light */
    }
    a {
        color: #87CEEB; /* Light blue for links */
    }
    strong {
        color: #f8f9fa; /* Ensures bold text is clearly visible */
    }
    /* Custom style for the footer to make it more distinct */
    .stApp footer {
        visibility: hidden; /* Hide default Streamlit footer */
    }
</style>
""", unsafe_allow_html=True)

# Import AdvancedPhishingDetector AFTER set_page_config
from training import AdvancedPhishingDetector

# Ensure the 'models' directory exists for saving/loading models
if not os.path.exists('models'):
    os.makedirs('models')

@st.cache_resource # Cache the detector to avoid re-initializing and reloading models on every rerun
def get_detector():
    """Initializes and loads the AdvancedPhishingDetector,
    providing a warning if models are not found."""
    detector = AdvancedPhishingDetector()
    if not detector.load_models():
        st.warning("Pre-trained models not found. Please run 'python training.py' first to train and save the models, or use the 'Train Sample Model' button below for a quick demo setup.")
    return detector

# Initialize the detector
detector = get_detector()

st.title("🛡️ Advanced Phishing URL Detector")
st.markdown("""
<div style="text-align: center; margin-bottom: 2.5rem; font-size: 1.15em; color: #adb5bd;">
    Uncover malicious links! Enter a URL below to check if it's a legitimate or phishing website.
    <br>
    <span style="font-size: 0.9em; color: #ced4da;">
        This intelligent detector leverages an ensemble of machine learning models and comprehensive feature extraction
        (URL structure, content, network, WHOIS, DNS) to provide a prediction and risk assessment.
    </span>
</div>
""", unsafe_allow_html=True)


# --- URL Input Section ---
st.subheader("🔗 URL Analysis")
with st.container(border=True): # Use a container for better visual grouping
    user_url = st.text_input("Input URL to Analyze:", "https://www.google.com", help="e.g., https://www.google.com or http://bad-phish.gq/login?user=admin")

    col1, col2 = st.columns([1, 1]) # Use columns for button alignment
    with col1:
        analyze_button = st.button("🚀 Analyze URL", type="primary")
    with col2:
        # Add a clear button or another action if needed
        if st.button("Clear Input"):
            user_url = "" # Clear the input
            st.rerun() # Rerun to clear the text input and results


if analyze_button:
    if user_url:
        with st.spinner("Analyzing URL... This might take a moment due to network requests and feature extraction. Please wait."):
            try:
                prediction_result = detector.predict_single_url(user_url, detailed=True)

                st.markdown("---")
                st.subheader("📊 Analysis Result")

                if prediction_result.get('prediction') == 'Error':
                    st.error(f"❌ Error analyzing URL: {prediction_result.get('error', 'Unknown error during analysis.')} Please check the URL format or your internet connection.")
                else:
                    st.write(f"**URL:** `{prediction_result['url']}`")

                    # Display prediction with distinct styling
                    if prediction_result['prediction'] == 'Phishing':
                        st.markdown(f'<div class="phishing-prediction"><h3>🚨 Prediction: <span style="color: #FA8072;">PHISHING!</span></h3></div>', unsafe_allow_html=True)
                        st.error("This URL is highly likely to be a phishing attempt. Exercise extreme caution and do not interact with it.")
                    else:
                        st.markdown(f'<div class="legitimate-prediction"><h3>✅ Prediction: <span style="color: #90EE90;">LEGITIMATE</span></h3></div>', unsafe_allow_html=True)
                        st.success("This URL appears to be legitimate. However, always remain vigilant when Browse online.")

                    # Display key metrics in columns for better layout
                    col_prob1, col_prob2, col_conf = st.columns(3) # Removed risk level from metric row as it's custom styled below
                    with col_prob1:
                        st.metric(label="Phishing Probability", value=f"{prediction_result['phishing_probability']:.2f}")
                    with col_prob2:
                        st.metric(label="Legitimate Probability", value=f"{prediction_result['legitimate_probability']:.2f}")
                    with col_conf:
                        st.metric(label="Confidence Score", value=f"{prediction_result['confidence']:.2f}")

                    # Conditional styling for risk level (separate line for prominence)
                    risk_level_text = prediction_result['risk_level']
                    # Updated risk level colors for dark theme
                    risk_color = "#FA8072" if risk_level_text in ['Very High', 'High'] else "#FFD700" if risk_level_text == 'Medium' else "#90EE90"
                    st.markdown(f"**Overall Risk Level:** <span style='font-size: 1.2em; font-weight: bold; color: {risk_color};'>{risk_level_text}</span>", unsafe_allow_html=True)


                    st.subheader("🕵️ Suspicious Indicators Found:")
                    if prediction_result['suspicious_indicators']:
                        # Dark theme specific color for indicator text
                        st.markdown(f"<p style='color: #FFD700;'>") # Yellow for warnings
                        for indicator in prediction_result['suspicious_indicators']:
                            st.markdown(f"- ⚠️ {indicator}") # Added warning emoji
                        st.markdown(f"</p>")
                    else:
                        st.markdown("<p style='color: #90EE90;'>✅ No significant suspicious indicators found for this URL.</p>", unsafe_allow_html=True)

                    # Detailed expanders
                    if prediction_result.get('individual_models'):
                        with st.expander("🔍 Individual Model Predictions"):
                            st.write("See how each underlying model contributed to the final decision:")
                            for model_name, model_data in prediction_result['individual_models'].items():
                                prediction_emoji = "🚨" if model_data['prediction'] == 'Phishing' else "✅"
                                # Adjust text color for model predictions
                                model_text_color = "#FA8072" if model_data['prediction'] == 'Phishing' else "#90EE90"
                                st.markdown(f"**{model_name.replace('_', ' ').title()}**: {prediction_emoji} Prediction: <span style='color:{model_text_color};'>`{model_data['prediction']}`</span> (Probability: `{model_data['phishing_probability']:.2f}`)", unsafe_allow_html=True)

                    with st.expander("🔬 Extracted Features (Raw Data)"):
                        st.json(prediction_result['features'])

            except Exception as e:
                st.error(f"Oops! An unexpected error occurred during URL analysis: {e}. This might be due to an invalid URL, network issues, or missing dependencies. Please check the URL or try again later.")
    else:
        st.warning("Please enter a URL in the text box above and click 'Analyze URL' to proceed.")

st.markdown("---")
st.subheader("⚙️ Model Management (For Setup & Demo)")
st.markdown("""
<div style="font-size: 0.95em; color: #adb5bd;">
    If you haven't trained the models yet, or if they couldn't be loaded, you can train a basic model
    using a diverse set of sample data. This will utilize the comprehensive dataset embedded directly in the `training.py` script.
    <br>
    <strong>Note:</strong> This training process is for demonstration and initial setup. For robust, real-world deployment,
    it's highly recommended to train the models offline with a much larger and more diverse dataset,
    ensuring your environment has all necessary dependencies (e.g., <code>dnspython</code>, <code>python-whois</code>).
</div>
""", unsafe_allow_html=True)

# Placeholder for the training data (assuming AdvancedPhishingDetector will handle this internally if not passed)
# This button will trigger the training process within the detector,
# which will use the hardcoded sample data.
if st.button("🔁 Train Sample Model", help="Trains the machine learning models with a small, embedded dataset for demonstration and initial setup. This will overwrite any existing models."):
    with st.spinner("Training models with sample data... This may take several minutes depending on your internet speed and system resources, as it involves network requests for feature extraction. Please be patient."):
        # The detector.train_models() method is expected to use its internal sample data
        # or require it to be passed. Given your original code, it expects `urls` and `labels`.
        # I'll replicate the data passing here for clarity, though in a real app,
        # you might abstract this into the detector's class.
        legitimate_urls = [
            'https://www.google.com', 'https://www.facebook.com', 'https://www.amazon.com', 'https://www.microsoft.com',
            'https://www.apple.com', 'https://www.paypal.com', 'https://www.ebay.com', 'https://www.twitter.com',
            'https://www.instagram.com', 'https://www.linkedin.com', 'https://www.netflix.com',
            'https://www.spotify.com', 'https://www.youtube.com',
            'https://www.github.com', 'https://www.reddit.com', 'https://www.wikipedia.org',
            'https://www.stackoverflow.com', 'https://www.dropbox.com', 'https://www.zoom.us',
            'https://www.slack.com', 'https://www.adobe.com', 'https://www.salesforce.com',
            'https://www.oracle.com', 'https://www.ibm.com', 'https://www.intel.com',
            'https://www.nvidia.com', 'https://www.samsung.com', 'https://www.sony.com',
            'https://www.hp.com', 'https://www.dell.com', 'https://www.cisco.com',
            'https://www.vmware.com', 'https://www.shopify.com', 'https://www.squarespace.com',
            'https://www.wordpress.com', 'https://www.twitch.tv', 'https://www.tiktok.com',
            'https://www.snapchat.com', 'https://www.pinterest.com', 'https://www.tumblr.com',
            'https://www.mailchimp.com', 'https://www.constantcontact.com', 'https://www.wix.com',
            'https://www.godaddy.com', 'https://www.namecheap.com', 'https://www.bluehost.com',
            'https://www.hostgator.com', 'https://www.cloudflare.com', 'https://www.aws.amazon.com',
            'https://www.azure.microsoft.com', 'https://www.chase.com', 'https://www.bankofamerica.com',
            'https://www.wellsfargo.com', 'https://www.citibank.com', 'https://www.capitalone.com',
            'https://www.americanexpress.com', 'https://www.discover.com', 'https://www.visa.com',
            'https://www.mastercard.com', 'https://www.usbank.com', 'https://www.pnc.com',
            'https://www.tdbank.com', 'https://www.schwab.com', 'https://www.fidelity.com',
            'https://www.vanguard.com', 'https://www.etrade.com', 'https://www.robinhood.com',
            'https://www.coinbase.com', 'https://www.binance.com', 'https://www.kraken.com',
            'https://www.gemini.com', 'https://www.bitfinex.com', 'https://www.walmart.com',
            'https://www.target.com', 'https://www.bestbuy.com', 'https://www.homedepot.com',
            'https://www.lowes.com', 'https://www.macys.com', 'https://www.kohls.com',
            'https://www.jcpenney.com', 'https://www.nordstrom.com', 'https://www.costco.com',
            'https://www.samsclub.com', 'https://www.alibaba.com', 'https://www.aliexpress.com',
            'https://www.wish.com', 'https://www.etsy.com', 'https://www.overstock.com',
            'https://www.wayfair.com', 'https://www.booking.com', 'https://www.expedia.com',
            'https://www.trivago.com', 'https://www.hotels.com', 'https://www.airbnb.com',
            'https://www.uber.com', 'https://www.lyft.com', 'https://www.doordash.com',
            'https://www.grubhub.com', 'https://www.ubereats.com', 'https://www.postmates.com',
            'https://www.instacart.com', 'https://www.shipt.com', 'https://www.cnn.com',
            'https://www.bbc.com', 'https://www.nytimes.com', 'https://www.washingtonpost.com',
            'https://www.reuters.com', 'https://www.bloomberg.com', 'https://www.wsj.com',
            'https://www.usatoday.com', 'https://www.foxnews.com', 'https://www.msnbc.com',
        ]

        phishing_urls = [
            'http://paypaI.com-security-update.tk', 'https://amazon-security.ml', 'http://apple-id-verify.ga',
            'https://microsoft-account-suspended.cf', 'http://google-security-alert.gq',
            'https://facebook-security-check.tk', 'http://instagram-verify-account.ml',
            'https://twitter-suspended-account.ga', 'http://linkedin-account-limited.cf',
            'https://ebay-account-review.gq', 'http://netfIix-billing-update.tk',
            'https://spotify-premium-expired.ml', 'http://paypal-account-verification.ga',
            'https://amazon-prime-renewal.cf', 'http://apple-icloud-storage.gq',
            'https://microsoft-office-expired.tk', 'http://google-drive-storage-full.ml',
            'https://facebook-account-disabled.ga', 'http://instagram-copyright-violation.cf',
            'https://twitter-account-suspended.gq', 'http://linkedin-premium-expired.tk',
            'https://ebay-seller-fees-due.ml', 'http://netflix-payment-failed.ga',
            'https://spotify-account-hacked.cf', 'http://paypal-unusual-activity.gq',
            'https://amazon-order-cancelled.tk', 'http://apple-app-store-refund.ml',
            'https://microsoft-security-breach.ga', 'http://google-account-compromised.cf',
            'https://facebook-login-attempt.gq', 'http://instagram-new-message.tk',
            'https://twitter-dm-notification.ml', 'http://linkedin-connection-request.ga',
            'https://ebay-bid-confirmation.cf', 'http://netflix-new-device-login.gq',
            'https://spotify-playlist-shared.tk', 'http://paypal-money-received.ml',
            'https://amazon-package-delivery.ga', 'http://apple-warranty-expired.cf',
            'https://microsoft-update-required.gq', 'http://google-photos-backup-full.tk',
            'https://facebook-friend-request.ml', 'http://instagram-story-mention.ga',
            'https://twitter-trending-notification.cf', 'http://linkedin-job-alert.gq',
            'https://ebay-auction-ending.tk', 'http://chase-bank-alert.ml',
            'https://bankofamerica-security.ga', 'http://wellsfargo-account-locked.cf',
            'https://citibank-fraud-alert.gq', 'http://capitalone-payment-due.tk',
            'https://americanexpress-reward.ml', 'http://discover-cashback-ready.ga',
            'https://visa-transaction-declined.cf', 'http://mastercard-security-code.gq',
            'https://usbank-mobile-banking.tk', 'http://pnc-account-update.ml',
            'https://tdbank-wire-transfer.ga', 'http://schwab-investment-alert.cf',
            'https://fidelity-portfolio-update.gq', 'http://vanguard-dividend-payment.tk',
            'https://etrade-margin-call.ml', 'http://robinhood-stock-alert.ga',
            'https://coinbase-price-alert.cf', 'http://binance-withdrawal-confirm.gq',
            'https://kraken-deposit-received.tk', 'http://gemini-account-verified.ml',
            'https://bitfinex-trading-suspended.ga', 'http://walmart-order-ready.cf',
            'https://target-pickup-notification.gq', 'http://bestbuy-price-match.tk',
            'https://homedepot-delivery-update.ml', 'http://lowes-store-pickup.ga',
            'https://macys-sale-notification.cf', 'http://kohls-rewards-earned.gq',
            'https://jcpenney-coupon-expires.tk', 'http://nordstrom-item-restocked.ml',
            'https://costco-membership-renewal.ga', 'http://samsclub-gas-discount.cf',
            'https://alibaba-supplier-message.gq', 'http://aliexpress-shipment-delay.tk',
            'https://wish-order-processing.ml', 'http://etsy-shop-notification.ga',
            'https://overstock-flash-sale.cf', 'http://wayfair-delivery-scheduled.gq',
            'https://booking-reservation-confirm.tk', 'http://expedia-flight-cancelled.ml',
            'https://trivago-price-drop.ga', 'http://hotels-booking-modified.cf',
            'https://airbnb-host-message.gq', 'http://uber-trip-receipt.tk',
            'https://lyft-ride-rating.ml', 'http://doordash-order-delivered.ga',
            'https://grubhub-restaurant-closed.cf', 'http://ubereats-refund-processed.gq',
            'https://postmates-delivery-issue.tk', 'http://instacart-shopper-message.ml',
            'https://shipt-order-substitution.ga', 'http://amazon-aws-billing.cf',
            'https://microsoft-azure-usage.gq', 'http://google-cloud-quota.tk',
            'https://dropbox-storage-upgrade.ml', 'http://zoom-meeting-recording.ga',
            'https://slack-workspace-invite.cf', 'http://adobe-subscription-renewal.gq',
            'https://salesforce-license-expired.tk', 'http://oracle-support-ticket.ml',
            'https://ibm-cloud-maintenance.ga', 'http://intel-driver-update.cf',
            'https://nvidia-gpu-warranty.gq', 'http://samsung-device-recall.tk',
            'https://sony-product-registration.ml', 'http://hp-printer-cartridge.ga',
            'https://dell-warranty-extension.cf', 'http://cisco-security-patch.gq',
            'https://vmware-license-activation.tk', 'http://shopify-payment-gateway.ml',
            'https://squarespace-domain-renewal.ga', 'http://wordpress-plugin-update.cf',
            'https://twitch-subscriber-badge.gq', 'http://tiktok-video-violation.tk',
            'https://snapchat-friend-added.ml', 'http://pinterest-board-shared.ga',
            'http://tumblr-post-flagged.cf', 'http://mailchimp-campaign-sent.gq',
            'https://constantcontact-list-import.tk', 'http://wix-site-published.ml',
            'https://godaddy-domain-transfer.ga', 'http://namecheap-ssl-certificate.cf',
            'https://bluehost-backup-complete.gq', 'http://hostgator-server-migration.tk',
            'https://cloudflare-ddos-protection.ml', 'http://github-repository-forked.ga',
            'https://stackoverflow-answer-accepted.cf', 'http://reddit-comment-reply.gq',
            'https://wikipedia-article-edited.tk', 'http://youtube-video-monetized.ml',
            'https://netflix-account-sharing.ga', 'http://spotify-family-plan.cf',
            'https://paypal-business-account.gq', 'http://apple-developer-program.tk',
            'https://microsoft-partner-network.ml', 'http://google-ads-campaign.ga',
            'https://facebook-business-manager.cf', 'http://instagram-creator-fund.gq',
            'https://twitter-api-access.tk', 'http://linkedin-sales-navigator.ml',
            'https://ebay-managed-payments.ga',
        ]

        full_urls = legitimate_urls + phishing_urls
        full_labels = [0] * len(legitimate_urls) + [1] * len(phishing_urls)

        try:
            results = detector.train_models(
                urls=full_urls,
                labels=full_labels
            )
            st.success("🎉 Models trained and saved successfully! You can now analyze URLs with enhanced accuracy.")

            # Optional: Test a known phishing URL after training for immediate feedback
            st.markdown("---")
            st.subheader("Quick Test After Training:")
            test_url_after_train = "http://secure-logln.info/update?user=test"
            st.info(f"Automatically testing a sample phishing URL: `{test_url_after_train}`")
            test_result = detector.predict_single_url(test_url_after_train, detailed=True)
            if test_result['prediction'] == 'Phishing':
                st.markdown(f'<div class="phishing-prediction"><h3>🚨 Test Result: <span style="color: #FA8072;">PHISHING!</span></h3></div>', unsafe_allow_html=True)
            else:
                st.markdown(f'<div class="legitimate-prediction"><h3>✅ Test Result: <span style="color: #90EE90;">LEGITIMATE</span></h3></div>', unsafe_allow_html=True)
            st.write(f"Phishing Probability: **{test_result['phishing_probability']:.2f}**")
            st.write(f"Risk Level: **{test_result['risk_level']}**")


        except Exception as e:
            st.error(f"❌ Training or prediction failed: {str(e)}. Please ensure all dependencies are installed (e.g., `pip install -r requirements.txt`) and your internet connection is stable for feature extraction during training.")

# Footer
st.markdown(
    """
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    """,
    unsafe_allow_html=True
)
st.markdown("""
<div style="text-align: center; margin-top: 4rem; padding: 2.5rem; color: rgba(255, 255, 255, 0.65); background-color: #0d1117; border-top: 1px solid rgba(255, 255, 255, 0.15); border-radius: 1rem 1rem 0 0; box-shadow: 0 -5px 15px rgba(0,0,0,0.4);">
    <div style="font-size: 1rem; font-weight: 500;">
        🛡️ <span style="color: #00BFFF;">Phishing Shield</span> - Advanced AI Security Analysis<br>
        <em>Empowering safe Browse with cutting-edge machine learning</em>
    </div>
    <div style="margin-top: 2rem; font-size: 0.85rem; color: rgba(255, 255, 255, 0.5);">
        © 2025 Satyaki Abhijit. All rights reserved.
    </div>
    <div style="margin-top: 1.5rem;">
        <a href="https://github.com/satyakiabhijit" target="_blank" style="color: #87CEEB; text-decoration: none; margin: 0 0.8rem; transition: color 0.3s ease;" title="GitHub Profile">
            <i class="fab fa-github fa-xl"></i>
        </a>
        <a href="https://abhijitsatyaki.42web.io" target="_blank" style="color: #87CEEB; text-decoration: none; margin: 0 0.8rem; transition: color 0.3s ease;" title="Portfolio Website">
            <i class="fa-solid fa-earth-americas fa-xl"></i>
        </a>
        <a href="mailto:abhijitsatyaki29@gmail.com" target="_blank" style="color: #87CEEB; text-decoration: none; margin: 0 0.8rem; transition: color 0.3s ease;" title="Send Email">
            <i class="fa-solid fa-envelope fa-xl"></i>
        </a>
        </div>
</div>
""", unsafe_allow_html=True)