import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.core.database import Base, get_db
from app.main import app

# In-memory SQLite with StaticPool so all connections share the same memory instance
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function")
def db_session():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def student_management_code() -> str:
    return """from datetime import datetime


students = []


def calculate_percentage(marks):
    total = sum(marks)
    percentage = (total / (len(marks) * 100)) * 100
    return round(percentage, 2)


def calculate_grade(percentage):
    if percentage >= 90:
        return "A+"
    elif percentage >= 80:
        return "A"
    elif percentage >= 70:
        return "B"
    elif percentage >= 60:
        return "C"
    elif percentage >= 40:
        return "D"
    else:
        return "F"


def add_student(student_id, name, age, marks):
    student = {
        "id": student_id,
        "name": name,
        "age": age,
        "marks": marks,
        "created_at": datetime.now().isoformat()
    }

    students.append(student)
    print(f"Student {name} added successfully.")


def find_student(student_id):
    for student in students:
        if student["id"] == student_id:
            return student

    return None


def update_student_marks(student_id, new_marks):
    student = find_student(student_id)

    if student is None:
        print("Student not found.")
        return False

    student["marks"] = new_marks
    print("Marks updated successfully.")
    return True


def generate_report(student_id):
    student = find_student(student_id)

    if student is None:
        print("Student not found.")
        return None

    percentage = calculate_percentage(student["marks"])
    grade = calculate_grade(percentage)

    report = {
        "student_id": student["id"],
        "name": student["name"],
        "percentage": percentage,
        "grade": grade,
        "passed": percentage >= 40,
        "attendance": student["attendance"]
    }

    return report


def search_students(keyword):
    results = []

    for student in students:
        if keyword.lower() in student["name"]:
            results.append(student)

    return results


def delete_student(student_id):
    student = find_student(student_id)

    if student is None:
        return False

    students.remove(student)
    return True


def display_all_students():
    for student in students:
        print(
            student["id"],
            student["name"],
            student["age"],
            student["marks"]
        )


def main():
    add_student(101, "Aarav Patel", 20, [85, 90, 78])
    add_student(102, "Diya Shah", -5, [75, 80, 95])
    add_student(103, "Rohan Mehta", 21, [])

    update_student_marks(101, [90, 95, 100])

    print("\\nStudent Report:")
    report = generate_report(101)
    print(report)

    print("\\nSearch Results:")
    print(search_students("AARAV"))

    print("\\nUnknown Student Report:")
    print(generate_report(999))

    print("\\nAll Students:")
    display_all_students()


if __name__ == "__main__":
    main()
"""
