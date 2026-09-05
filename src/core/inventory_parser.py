import os
import json
import pandas as pd
from datetime import datetime, timezone
from src.db.database import SessionLocal, AssetInventoryVersion, Finding

INVENTORY_DIR = "data/inventory"
os.makedirs(INVENTORY_DIR, exist_ok=True)

def generate_csv_and_check_delta(company_name: str, asset_category: str = "Comprehensive Inventory", new_data: list = None, columns: list = None, mcp_server_id: int = None):
    """
    Generates a new CSV for the asset inventory.
    If a previous version exists, it runs a delta check and raises alerts for negative changes.
    Returns the path to the new CSV.
    """
    if new_data is None:
        new_data = []
    if columns is None:
        columns = []
        
    display_category = asset_category.replace("_", " ") if asset_category else "Comprehensive Inventory"
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    sanitized_company = company_name.replace(" ", "_") if company_name else "UnknownCompany"
    sanitized_category = asset_category.replace(" ", "_") if asset_category else "Comprehensive_Inventory"
    
    file_name = f"{sanitized_company}_{sanitized_category}_{timestamp}.csv"
    file_path = os.path.join(INVENTORY_DIR, file_name)
    
    # Sanitize rows to ensure all nested lists, dicts, and unhashable objects are serialized
    sanitized_data = []
    for row in new_data:
        sanitized_row = {}
        for k, v in row.items():
            if isinstance(v, (list, dict)):
                sanitized_row[k] = json.dumps(v)
            else:
                sanitized_row[k] = v
        sanitized_data.append(sanitized_row)
        
    df_new = pd.DataFrame(sanitized_data, columns=columns)
    df_new.to_csv(file_path, index=False)
    
    db = SessionLocal()
    negative_alerts_count = 0
    delta_path = None
    
    try:
        # Find previous version
        prev_version = db.query(AssetInventoryVersion)\
            .filter(
                AssetInventoryVersion.company_name == company_name,
                AssetInventoryVersion.asset_category.in_([display_category, asset_category, "Comprehensive Inventory", "Comprehensive_Inventory"])
            )\
            .order_by(AssetInventoryVersion.created_at.desc()).first()
            
        if prev_version and prev_version.file_path and os.path.exists(prev_version.file_path):
            try:
                df_old = pd.read_csv(prev_version.file_path).fillna("").astype(str)
                df_new_str = df_new.fillna("").astype(str)
                
                common_cols = list(set(df_new_str.columns) & set(df_old.columns))
                if common_cols:
                    df_diff = df_new_str.merge(df_old, on=common_cols, indicator=True, how='outer')
                    
                    df_added = df_diff[df_diff['_merge'] == 'left_only'].drop('_merge', axis=1)
                    df_removed = df_diff[df_diff['_merge'] == 'right_only'].drop('_merge', axis=1)
                    
                    if not df_added.empty or not df_removed.empty:
                        delta_name = f"delta_{sanitized_company}_{sanitized_category}_{timestamp}.csv"
                        delta_path = os.path.join(INVENTORY_DIR, delta_name)
                        
                        df_added['Delta_Status'] = 'ADDED'
                        df_removed['Delta_Status'] = 'REMOVED'
                        df_delta = pd.concat([df_added, df_removed])
                        df_delta.to_csv(delta_path, index=False)
                        
                        for _, row in df_removed.iterrows():
                            negative_alerts_count += 1
                            alert = Finding(
                                control_name=f"Inventory Change Alert: {display_category}",
                                severity="P2 High",
                                description=f"An asset was removed or degraded in category {display_category}.",
                                evidence_snippet=str(row.to_dict()),
                                status="Non-Compliant"
                            )
                            db.add(alert)
                            
                        db.commit()
            except Exception as delta_e:
                print(f"[Inventory Delta] Delta check warning: {delta_e}")
                
        # Save new version record
        new_version = AssetInventoryVersion(
            company_name=company_name or "UnknownCompany",
            asset_category=display_category,
            file_path=file_path,
            delta_path=delta_path,
            negative_alerts=negative_alerts_count
        )
        db.add(new_version)
        db.commit()
        db.refresh(new_version)
        print(f"[Inventory] Successfully saved version #{new_version.id} for {display_category}")
        
    except Exception as e:
        print(f"Error generating inventory CSV: {str(e)}")
    finally:
        db.close()
        
    return file_path
