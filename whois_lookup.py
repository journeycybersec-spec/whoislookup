import whois
import datetime
import sys

# Function to perform WHOIS lookup
def get_whois_data(domain):
    try:
        w = whois.whois(domain)
        return w
    except Exception as e:
        print(f"Error: Could not fetch WHOIS data for {domain}")
        print(e)
        sys.exit(1)

# Function to calculate domain age
def get_domain_age(whois_data):
    creation_date = whois_data.creation_date
    if isinstance(creation_date, list):
        creation_date = creation_date[0]

    # Make the current datetime offset-aware, or make creation_date naive
    if creation_date.tzinfo is not None:
        creation_date = creation_date.astimezone(datetime.timezone.utc).replace(tzinfo=None)

    domain_age = datetime.datetime.now() - creation_date
    return domain_age.days

# Function to extract registrant organization
def get_registrant_organization(whois_data):
    return whois_data.get("org", "N/A")

# Function to check if the domain is using DNSSEC
def get_dnssec_status(whois_data):
    return whois_data.get("dnssec", "N/A")

# Function to detect frequent ownership changes
def ownership_change_check(whois_data):
    return whois_data.get("registrar", "Unknown")

# Function to format datetime objects into human-readable format
def format_datetime(dt):
    if isinstance(dt, datetime.datetime):
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    elif isinstance(dt, list):
        # If it's a list, take the last updated date (latest timestamp)
        try:
            dt = dt[-1]  # Take the latest update
            # Check if it's a string and parse it
            if isinstance(dt, str):
                dt = datetime.datetime.strptime(dt, "%Y-%m-%d %H:%M:%S")
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError):
            return "Invalid date format"
    elif isinstance(dt, str):
        # If it's a string, check if it's in ISO 8601 format (e.g., "2025-08-14T07:11:34Z")
        try:
            dt = datetime.datetime.strptime(dt, "%Y-%m-%dT%H:%M:%SZ")
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            return dt  # Return the original string if parsing fails
    return "N/A"

# Function to format domain status properly
def format_domain_status(status):
    if isinstance(status, list):
        return ", ".join(status)
    return status

# Function to check for red flags and visually display them
def check_red_flags(domain, whois_data):
    red_flags = []
    results = {}
    
    # Red flag 1: New domain (<6 months)
    domain_age = get_domain_age(whois_data)
    if domain_age < 180:
        results["New domain (under 6 months)"] = "Not Safe ❌"
        red_flags.append("New domain (under 6 months)")
    else:
        results["New domain (under 6 months)"] = "Safe ✅"

    # Red flag 2: Anonymous registrants with shady patterns
    registrant_org = get_registrant_organization(whois_data)
    if registrant_org and "anonymous" in registrant_org.lower():
        results["Anonymous registrant detected"] = "Not Safe ❌"
        red_flags.append("Anonymous registrant detected")
    else:
        results["Anonymous registrant detected"] = "Safe ✅"
    
    # Red flag 3: Frequent ownership changes
    ownership_history = ownership_change_check(whois_data)
    if "frequent" in ownership_history.lower():  # Placeholder for more advanced checks
        results["Frequent ownership changes detected"] = "Not Safe ❌"
        red_flags.append("Frequent ownership changes detected")
    else:
        results["Frequent ownership changes detected"] = "Safe ✅"
    
    # Red flag 4: Check for DNSSEC status
    dnssec_status = get_dnssec_status(whois_data)
    if dnssec_status == "N/A":
        results["No DNSSEC found"] = "Not Safe ❌"
        red_flags.append("No DNSSEC found")
    else:
        results["No DNSSEC found"] = "Safe ✅"

    # Red flag 5: Potential offshore registrar (a simplistic check based on registrar)
    if "offshore" in whois_data.registrar.lower():
        results["Offshore registrar detected"] = "Not Safe ❌"
        red_flags.append("Offshore registrar detected")
    else:
        results["Offshore registrar detected"] = "Safe ✅"
    
    # Final judgment
    final_judgment = "Safe ✅" if not red_flags else "Not Safe ❌"
    
    return results, final_judgment

# Main function to run the lookup and display information
def whois_lookup(domain):
    print(f"\nPerforming WHOIS lookup for {domain}...\n")
    whois_data = get_whois_data(domain)

    # Header and Domain Information
    print(f"Domain Information for: {domain}")
    print("=" * 40)
    
    # Registered On, Expires On, Updated On
    print(f"Registered On    : {format_datetime(whois_data.creation_date)}")
    print(f"Expires On       : {format_datetime(whois_data.expiration_date)}")
    print(f"Updated On       : {format_datetime(whois_data.updated_date)}")
    
    # Domain Status & Name Servers
    print(f"Domain Status    : {format_domain_status(whois_data.status)}")
    print(f"Name Servers     : {', '.join(whois_data.name_servers) if whois_data.name_servers else 'N/A'}")
    
    # Additional Information
    print("-" * 40)
    print(f"Registrant Organization : {get_registrant_organization(whois_data)}")
    print(f"Domain Age (Days)      : {get_domain_age(whois_data)} days")
    print(f"DNSSEC Status          : {get_dnssec_status(whois_data)}")

    # Check for red flags
    red_flags, final_judgment = check_red_flags(domain, whois_data)

    # Display Red Flags Checklist
    print("\nRed Flags Checklist:")
    for flag, result in red_flags.items():
        print(f" - {flag}: {result}")
    
    # Final Judgment
    print("\nFinal Judgment:")
    print(final_judgment)
    
    print("=" * 40)

# Entry point for CLI
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python whois_lookup.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]
    whois_lookup(domain)
