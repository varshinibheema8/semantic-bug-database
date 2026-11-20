
import psycopg2

def get_db_connection():
    try:
        connection = psycopg2.connect(
            host="localhost",
            database="semantic_bug_db",
            user="postgres",
            password="922r@922",
            port="5432"
        )
        return connection

    except Exception as e:
        print("Database connection error:", e)
        return None
