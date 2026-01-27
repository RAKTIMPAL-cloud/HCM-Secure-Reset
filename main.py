import streamlit as st
import requests
import pandas as pd
import json
import string
import secrets

# --- App Configuration ---
st.set_page_config(page_title="Oracle HCM Bulk User Creator", layout="wide")
st.title("👤 Oracle HCM Bulk User Creator")

# --- UI Layout ---
col1, col2 = st.columns([1, 1])

with col1:
    st.subheader("🌐 Connection Details")
    env_url = st.text_input("Environment URL", "https://iavnqy-dev2.fa.ocs.oraclecloud.com")
    username = st.text_input("Admin Username")
    password = st.text_input("Admin Password", type="password")

with col2:
    st.subheader("📁 Data Upload")
    uploaded_file = st.file_file_uploader("Upload Excel File", type=["xlsx"])
    st.caption("Required Columns: USER NAME, FIRST NAME, LAST NAME, WORK EMAIL")

# --- Logic Functions ---

def generate_secure_password(length=12):
    """Generates a secure password meeting Oracle standard policy."""
    alphabet = string.ascii_letters + string.digits + "!#$%"
    pwd = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice("!#$%")
    ]
    pwd += [secrets.choice(alphabet) for _ in range(length - 4)]
    secrets.SystemRandom().shuffle(pwd)
    return "".join(pwd)

def create_bulk_users(env_url, admin_user, admin_pwd, df):
    """Executes Bulk POST via SCIM REST API to create users."""
    scim_url = env_url.rstrip("/") + "/hcmRestApi/scim/Bulk"
    temp_password = "Welcome1"  # Or use generate_secure_password()
    
    operations = []
    
    for index, row in df.iterrows():
        # Mapping Excel columns to SCIM JSON Structure
        user_op = {
            "method": "POST",
            "path": "/Users",
            "bulkId": f"user_{index}",
            "data": {
                "schemas": ["urn:scim:schemas:core:2.0:User"],
                "userName": str(row['USER NAME']).strip(),
                "name": {
                    "familyName": str(row['LAST NAME']).strip(),
                    "givenName": str(row['FIRST NAME']).strip()
                },
                "emails": [{
                    "primary": True,
                    "value": str(row['WORK EMAIL']).strip(),
                    "type": "W"
                }],
                "active": True,
                "password": temp_password
            }
        }
        operations.append(user_op)

    payload = {
        "schemas": ["urn:scim:schemas:core:2.0:BulkRequest"],
        "failOnErrors": 1,
        "Operations": operations
    }

    response = requests.post(
        scim_url,
        json=payload,
        auth=(admin_user, admin_pwd),
        headers={"Content-Type": "application/json"}
    )
    return response

# --- Main Logic ---

if st.button("🚀 Create Bulk Users"):
    if not (username and password and uploaded_file):
        st.warning("⚠️ Please provide credentials and upload an Excel file.")
    else:
        try:
            # Read Excel
            df = pd.read_excel(uploaded_file)
            
            # Clean column names (remove leading/trailing spaces)
            df.columns = [c.strip().upper() for c in df.columns]
            
            required_cols = ['USER NAME', 'FIRST NAME', 'LAST NAME', 'WORK EMAIL']
            if all(col in df.columns for col in required_cols):
                
                with st.spinner("📡 Sending Bulk Request to Oracle HCM..."):
                    res = create_bulk_users(env_url, username, password, df)
                    
                    if res.status_code in [200, 201]:
                        st.success("🎊 Bulk Creation Processed!")
                        
                        # Parse results
                        results = res.json().get("Operations", [])
                        status_rows = []
                        for i, op in enumerate(results):
                            status_code = str(op.get("status", {}).get("code", "N/A"))
                            status_rows.append({
                                "Row": i + 1,
                                "User Name": df.iloc[i]['USER NAME'],
                                "HTTP Status": status_code,
                                "Outcome": "✅ Created" if status_code.startswith("2") else "❌ Failed"
                            })
                        st.table(pd.DataFrame(status_rows))
                    else:
                        st.error(f"❌ API Error: {res.status_code} - {res.text}")
            else:
                st.error(f"❌ Missing columns. Please ensure the file has: {', '.join(required_cols)}")
        
        except Exception as e:
            st.error(f"🔥 An error occurred: {e}")

# Footer
st.markdown("""
<hr style="margin-top: 50px;">
<div style='text-align: center; color: #888; font-size: 0.85em;'>
    <p>App developed by <strong>Raktim Pal</strong></p>
    <p>© 2026 Raktim Pal. All rights reserved.</p>
</div>
""", unsafe_allow_html=True)
