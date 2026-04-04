from pymongo import MongoClient
import sys

def migrate_local_to_atlas():
    local_uri = 'mongodb://localhost:27017/'
    remote_uri = 'mongodb+srv://GVP:QeMjUCPTfgZJVHVO@gvp.sbsdal5.mongodb.net/?appName=GVP'
    db_name = 'gayatri_school'

    print("[*] Connecting to local MongoDB...")
    try:
        local_client = MongoClient(local_uri)
        local_db = local_client[db_name]
    except Exception as e:
        print(f"[!] Failed to connect to local DB: {e}")
        return

    print("[*] Connecting to MongoDB Atlas...")
    try:
        remote_client = MongoClient(remote_uri)
        remote_db = remote_client[db_name]
    except Exception as e:
        print(f"[!] Failed to connect to Atlas DB: {e}")
        return

    collections = local_db.list_collection_names()
    
    if not collections:
        print("[-] No collections found in the local database or database doesn't exist.")
        return
        
    print(f"[*] Found collections: {collections}")

    for coll_name in collections:
        print(f"\n---> Migrating collection: '{coll_name}'")
        local_coll = local_db[coll_name]
        remote_coll = remote_db[coll_name]

        # Get all local documents
        docs = list(local_coll.find({}))
        
        if len(docs) > 0:
            print(f"[*] Found {len(docs)} documents in local '{coll_name}'.")
            
            # Clear existing data in remote collection (Optional but recommended to avoid duplicate IDs)
            remote_coll.delete_many({})
            print(f"[*] Cleared existing remote documents in '{coll_name}'.")
            
            # Insert to Atlas
            remote_coll.insert_many(docs)
            print(f"[+] Successfully migrated {len(docs)} documents to Atlas.")
        else:
            print(f"[-] Collection '{coll_name}' is empty. Skipping.")

    print("\n[✔] Data migration completed successfully!")

if __name__ == '__main__':
    migrate_local_to_atlas()
