import os
import json
import pandas as pd
from datetime import datetime, timezone
from src.db.database import SessionLocal, AssetInventoryVersion, Finding

INVENTORY_DIR = "data/inventory"
os.makedirs(INVENTORY_DIR, exist_ok=True)

def generate_csv_and_check_delta(company_name: str, asset_category: str, new_data: list, columns: list, mcp_server_id: int):
    """
    Generates a new CSV for the asset inventory.
    If a previous version exists, it runs a delta check and raises alerts for negative changes.
    Returns the path to the new CSV.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    sanitized_company = company_name.replace(" ", "_") if company_name else "UnknownCompany"
    sanitized_category = asset_category.replace(" ", "_") if asset_category else "UnknownCategory"
    
    file_name = f"{sanitized_company}_{sanitized_category}_{timestamp}.csv"
    file_path = os.path.join(INVENTORY_DIR, file_name)
    
    df_new = pd.DataFrame(new_data, columns=columns)
    df_new.to_csv(file_path, index=False)
    
    db = SessionLocal()
    try:
        # Find previous version
        prev_version = db.query(AssetInventoryVersion)\
            .filter_by(company_name=company_name, asset_category=asset_category)\
            .order_by(AssetInventoryVersion.created_at.desc()).first()
            
        negative_alerts_count = 0
        delta_path = None
        
        if prev_version and os.path.exists(prev_version.file_path):
            df_old = pd.read_csv(prev_version.file_path)
            
            # Simple delta: using a merge to find differences
            # For dataframes of varying columns, we ensure we only merge on common columns
            common_cols = list(set(df_new.columns) & set(df_old.columns))
            df_diff = df_new.merge(df_old, on=common_cols, indicator=True, how='outer')
            
            df_added = df_diff[df_diff['_merge'] == 'left_only'].drop('_merge', axis=1)
            df_removed = df_diff[df_diff['_merge'] == 'right_only'].drop('_merge', axis=1)
            
            if not df_added.empty or not df_removed.empty:
                # Save Delta
                delta_name = f"delta_{sanitized_company}_{sanitized_category}_{timestamp}.csv"
                delta_path = os.path.join(INVENTORY_DIR, delta_name)
                
                # Combine added/removed with a status column
                df_added['Delta_Status'] = 'ADDED'
                df_removed['Delta_Status'] = 'REMOVED'
                df_delta = pd.concat([df_added, df_removed])
                df_delta.to_csv(delta_path, index=False)
                
                # ALERT LOGIC: Negative Changes
                # E.g., if an asset was removed or modified negatively.
                for _, row in df_removed.iterrows():
                    negative_alerts_count += 1
                    alert = Finding(
                        control_name=f"Inventory Change Alert: {asset_category}",
                        severity="P2 High",
                        description=f"An asset was removed or degraded in category {asset_category}.",
                        evidence_snippet=str(row.to_dict()),
                        status="Non-Compliant"
                    )
                    db.add(alert)
                    
                db.commit()

        # Save new version record
        new_version = AssetInventoryVersion(
            company_name=company_name or "UnknownCompany",
            asset_category=asset_category or "UnknownCategory",
            file_path=file_path,
            delta_path=delta_path,
            negative_alerts=negative_alerts_count
        )
        db.add(new_version)
        db.commit()
        
    except Exception as e:
        print(f"Error generating inventory CSV: {str(e)}")
    finally:
        db.close()
        
    return file_path
