from fastapi import APIRouter
from typing import List
from pydantic import BaseModel

router = APIRouter(prefix="/samples", tags=["Sample Code Fixtures"])


class SampleSnippet(BaseModel):
    id: str
    title: str
    language: str
    description: str
    expected_vulnerabilities: List[str]
    code: str


SAMPLES: List[SampleSnippet] = [
    SampleSnippet(
        id="py-sqli-auth",
        title="Python: Vulnerable Auth & Database Service",
        language="python",
        description="A legacy authentication handler exhibiting SQL Injection, hardcoded secrets, and unsafe deserialization.",
        expected_vulnerabilities=[
            "SQL Injection via f-strings (CWE-89)",
            "Hardcoded JWT Secret Key (CWE-798)",
            "Insecure Deserialization via pickle (CWE-502)",
            "Bare except clause suppressing errors",
            "Timing attack in token comparison"
        ],
        code="""import os
import pickle
import sqlite3

# SECURITY RISK: Hardcoded secret key in source code
JWT_SECRET_KEY = "super_secret_jwt_signing_key_12345"

def authenticate_user(db_conn, username, password):
    cursor = db_conn.cursor()
    # SECURITY RISK: Direct f-string interpolation leads to SQL Injection
    query = f"SELECT id, role, password_hash FROM users WHERE username = '{username}'"
    cursor.execute(query)
    user = cursor.fetchone()
    
    if not user:
        return False
        
    # SECURITY RISK: Standard string equality is vulnerable to timing attacks
    if user[2] == password:
        return {"id": user[0], "role": user[1]}
    return False

def load_session_cache(serialized_data):
    try:
        # SECURITY RISK: Insecure deserialization can execute arbitrary code
        session = pickle.loads(serialized_data)
        return session
    except:
        # QUALITY ISSUE: Bare except clause suppresses critical exceptions
        return None
"""
    ),
    SampleSnippet(
        id="js-prototype-xss",
        title="JavaScript: User Profile & DOM Renderer",
        language="javascript",
        description="Client and server routines with DOM XSS, prototype pollution, loose equality, and weak randomness.",
        expected_vulnerabilities=[
            "Cross-Site Scripting (XSS) via innerHTML (CWE-79)",
            "Prototype Pollution in object merge (CWE-1321)",
            "Cryptographically weak randomness via Math.random() (CWE-338)",
            "Loose equality comparison (==)"
        ],
        code="""// Profile renderer and settings merger

function renderUserProfile(containerElement, userProfile) {
    // SECURITY RISK: Direct innerHTML assignment allows stored XSS
    containerElement.innerHTML = `
        <div class="profile-card">
            <h2>${userProfile.displayName}</h2>
            <p>${userProfile.bio}</p>
        </div>
    `;
}

function mergeUserSettings(target, customConfig) {
    for (let key in customConfig) {
        // SECURITY RISK: Unchecked key access causes Prototype Pollution
        if (typeof customConfig[key] === 'object') {
            target[key] = mergeUserSettings(target[key] || {}, customConfig[key]);
        } else {
            target[key] = customConfig[key];
        }
    }
    return target;
}

function generateSessionToken() {
    // SECURITY RISK: Math.random() is predictable and unsafe for session tokens
    return 'token_' + Math.random().toString(36).substring(2);
}

function checkAdminAccess(user) {
    // BUG: Loose equality allows unexpected type coercion bypasses
    if (user.role == 'admin') {
        return true;
    }
    return false;
}
"""
    ),
    SampleSnippet(
        id="java-pathtraversal-sql",
        title="Java: Document Exporter & SQL Query",
        language="java",
        description="A backend document retrieval servlet vulnerable to Path Traversal and JDBC SQL Injection.",
        expected_vulnerabilities=[
            "SQL Injection via string concatenation in Statement (CWE-89)",
            "Path Traversal via unvalidated File path (CWE-22)",
            "Weak Cryptographic Hash (MD5)",
            "String comparison using =="
        ],
        code="""import java.io.File;
import java.io.FileInputStream;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class DocumentService {
    private String baseDir = "/var/app/documents/";

    public byte[] downloadDocument(String filename) throws Exception {
        // SECURITY RISK: Path traversal enables reading arbitrary host files
        File file = new File(baseDir + filename);
        FileInputStream fis = new FileInputStream(file);
        byte[] data = new byte[(int) file.length()];
        fis.read(data);
        fis.close();
        return data;
    }

    public boolean verifyDocStatus(Connection conn, String docId, String status) throws Exception {
        // BUG: String comparison using reference equality instead of .equals()
        if (status == "APPROVED") {
            Statement stmt = conn.createStatement();
            // SECURITY RISK: JDBC SQL Injection
            String sql = "SELECT * FROM docs WHERE id = '" + docId + "' AND status = 'APPROVED'";
            ResultSet rs = stmt.executeQuery(sql);
            return rs.next();
        }
        return false;
    }
}
"""
    ),
    SampleSnippet(
        id="py-clean-refactored",
        title="Python: Secure Production Microservice",
        language="python",
        description="A properly architected Python service implementing parameterized queries, type safety, and secret encapsulation.",
        expected_vulnerabilities=[],
        code="""import os
import hmac
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

class SecureAuthService:
    def __init__(self, db_connection):
        self.db = db_connection
        self.secret_key = os.getenv("APP_SECRET_KEY")
        if not self.secret_key:
            raise ValueError("APP_SECRET_KEY environment variable is required.")

    def authenticate_user(self, username: str, password_hash: str) -> Optional[Dict[str, Any]]:
        cursor = self.db.cursor()
        # Parameterized query protects against SQL injection
        query = "SELECT id, username, password_hash, role FROM users WHERE username = %s"
        cursor.execute(query, (username,))
        row = cursor.fetchone()

        if not row:
            logger.info("Authentication failed: user not found")
            return None

        # Constant-time comparison prevents timing attacks
        if hmac.compare_digest(row[2], password_hash):
            return {"id": row[0], "username": row[1], "role": row[3]}

        return None
"""
    ),
    SampleSnippet(
        id="c-buffer-overflow-oob",
        title="C: Buffer Overflow & Memory Operations",
        language="c",
        description="A network packet processor with gets, strcpy, array out-of-bounds access, format string vulnerability, and unchecked malloc.",
        expected_vulnerabilities=[
            "Inherently Dangerous Function gets() (CWE-242)",
            "Unbounded String Copy strcpy() (CWE-120)",
            "Array Index Out-of-Bounds Access (CWE-119)",
            "Format String Vulnerability in printf() (CWE-134)",
            "Unchecked malloc() Return Value (CWE-476)"
        ],
        code="""#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void process_packet(const char *user_payload) {
    char header_buf[16];
    // SECURITY RISK: Unbounded copy causes buffer overflow
    strcpy(header_buf, user_payload);

    int packet_tags[4];
    // BUG: Array index 10 is past end of array capacity (4)
    packet_tags[10] = 999;

    // SECURITY RISK: Direct variable format string
    printf(user_payload);

    // BUG: Unchecked malloc return value before dereference
    char *session = (char *)malloc(128);
    session[0] = 'A';
}

int main(void) {
    char input[64];
    // SECURITY RISK: gets() cannot verify buffer bounds
    gets(input);
    process_packet(input);
    return 0;
}
"""
    ),
    SampleSnippet(
        id="cpp-resource-leak-slicing",
        title="C++: Resource Management & Memory Leaks",
        language="cpp",
        description="A cache manager with raw new leaks, new[]/delete mismatch, dangling local references, and exception slicing.",
        expected_vulnerabilities=[
            "Unmanaged Raw Allocation / Memory Leak (CWE-401)",
            "Deallocation Mismatch: Array new[] freed with scalar delete (CWE-762)",
            "Dangling Reference to Local Stack Variable (CWE-562)",
            "Exception Caught by Value Causing Object Slicing",
            "Manual Mutex Locking without RAII Guard (CWE-833)"
        ],
        code="""#include <iostream>
#include <string>
#include <mutex>
#include <stdexcept>

std::mutex cache_mutex;

// BUG: Returning reference to stack-allocated local object
const std::string& get_default_tag() {
    std::string tag = "SYSTEM_DEFAULT";
    return tag;
}

void allocate_cache_buffers() {
    // BUG: Raw heap allocation without corresponding delete
    int *metrics = new int[100];

    // BUG: Array new[] paired with scalar delete
    char *buffer = new char[256];
    delete buffer;

    // BUG: Manual mutex lock without RAII std::lock_guard
    cache_mutex.lock();
    // early return or exception here causes deadlock!
    cache_mutex.unlock();
}

void handle_request() {
    try {
        allocate_cache_buffers();
    } catch (std::runtime_error err) {
        // BUG: Exception caught by value causes object slicing
        std::cerr << "Caught error: " << err.what() << std::endl;
    }
}
"""
    )
]


@router.get("/", response_model=List[SampleSnippet])
def get_sample_snippets():
    """Returns curated demo code fixtures with known security vulnerabilities."""
    return SAMPLES
