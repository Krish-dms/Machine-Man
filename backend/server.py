from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional
import uuid
from datetime import datetime, timedelta
import jwt
import bcrypt
from enum import Enum

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT Configuration
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-change-in-production')
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# Create the main app without a prefix
app = FastAPI(title="JALPOOREE Maintenance System API")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Security
security = HTTPBearer()

# Enums
class UserRole(str, Enum):
    SUPER_ADMIN = "super_admin"
    USER = "user"

class ComplaintStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"

class ComplaintPriority(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class MachineStatus(str, Enum):
    OPERATIONAL = "operational"
    MAINTENANCE = "maintenance"
    OUT_OF_ORDER = "out_of_order"
    RETIRED = "retired"

# Models
class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    email: str
    password_hash: str
    role: UserRole = UserRole.USER
    full_name: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    is_active: bool = True

class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: UserRole = UserRole.USER
    full_name: str

class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    role: UserRole
    full_name: str
    created_at: datetime
    is_active: bool

class UserLogin(BaseModel):
    username: str
    password: str

class Machine(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    machine_id: str  # Custom machine identifier
    name: str
    type: str
    location: str
    specifications: Optional[str] = None
    status: MachineStatus = MachineStatus.OPERATIONAL
    last_maintenance: Optional[datetime] = None
    next_maintenance: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

class MachineCreate(BaseModel):
    machine_id: str
    name: str
    type: str
    location: str
    specifications: Optional[str] = None
    status: MachineStatus = MachineStatus.OPERATIONAL

class Complaint(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    machine_id: str
    reported_by: str  # User ID
    assigned_to: Optional[str] = None  # User ID
    status: ComplaintStatus = ComplaintStatus.PENDING
    priority: ComplaintPriority = ComplaintPriority.MEDIUM
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None
    resolution_notes: Optional[str] = None

class ComplaintCreate(BaseModel):
    title: str
    description: str
    machine_id: str
    priority: ComplaintPriority = ComplaintPriority.MEDIUM

class ComplaintUpdate(BaseModel):
    status: Optional[ComplaintStatus] = None
    assigned_to: Optional[str] = None
    priority: Optional[ComplaintPriority] = None
    resolution_notes: Optional[str] = None

class ActivityLog(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    action: str
    entity_type: str  # complaint, machine, user
    entity_id: str
    details: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

class DashboardStats(BaseModel):
    pending_complaints: int
    in_progress_complaints: int
    completed_complaints: int
    total_machines: int
    total_users: int

# Utility functions
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_access_token(user_id: str, username: str, role: str) -> str:
    expire = datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "exp": expire
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        user_doc = await db.users.find_one({"id": user_id})
        if user_doc is None:
            raise HTTPException(status_code=401, detail="User not found")
        
        return User(**user_doc)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def require_admin(current_user: User = Depends(get_current_user)):
    if current_user.role != UserRole.SUPER_ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

# Initialize default admin user
async def create_default_admin():
    existing_admin = await db.users.find_one({"username": "admin"})
    if not existing_admin:
        admin_user = User(
            username="admin",
            email="admin@jalpooree.com",
            password_hash=hash_password("admin123"),
            role=UserRole.SUPER_ADMIN,
            full_name="System Administrator"
        )
        await db.users.insert_one(admin_user.dict())

# Authentication Routes
@api_router.post("/auth/login", response_model=TokenResponse)
async def login(user_data: UserLogin):
    user_doc = await db.users.find_one({"username": user_data.username})
    if not user_doc or not verify_password(user_data.password, user_doc["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    if not user_doc["is_active"]:
        raise HTTPException(status_code=401, detail="Account is inactive")
    
    user = User(**user_doc)
    token = create_access_token(user.id, user.username, user.role)
    
    return TokenResponse(
        access_token=token,
        user=UserResponse(**user_doc)
    )

@api_router.get("/auth/me", response_model=UserResponse)
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    return UserResponse(**current_user.dict())

# Dashboard Routes
@api_router.get("/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats(current_user: User = Depends(get_current_user)):
    pending_count = await db.complaints.count_documents({"status": ComplaintStatus.PENDING})
    in_progress_count = await db.complaints.count_documents({"status": ComplaintStatus.IN_PROGRESS})
    completed_count = await db.complaints.count_documents({"status": ComplaintStatus.COMPLETED})
    total_machines = await db.machines.count_documents({})
    total_users = await db.users.count_documents({"is_active": True})
    
    return DashboardStats(
        pending_complaints=pending_count,
        in_progress_complaints=in_progress_count,
        completed_complaints=completed_count,
        total_machines=total_machines,
        total_users=total_users
    )

# User Management Routes
@api_router.post("/users", response_model=UserResponse)
async def create_user(user_data: UserCreate, admin_user: User = Depends(require_admin)):
    # Check if username exists
    existing_user = await db.users.find_one({"username": user_data.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # Check if email exists
    existing_email = await db.users.find_one({"email": user_data.email})
    if existing_email:
        raise HTTPException(status_code=400, detail="Email already exists")
    
    user = User(
        username=user_data.username,
        email=user_data.email,
        password_hash=hash_password(user_data.password),
        role=user_data.role,
        full_name=user_data.full_name
    )
    
    await db.users.insert_one(user.dict())
    
    # Log activity
    activity = ActivityLog(
        user_id=admin_user.id,
        action="create_user",
        entity_type="user",
        entity_id=user.id,
        details=f"Created user: {user.username}"
    )
    await db.activity_logs.insert_one(activity.dict())
    
    return UserResponse(**user.dict())

@api_router.get("/users", response_model=List[UserResponse])
async def get_users(admin_user: User = Depends(require_admin)):
    users = await db.users.find().to_list(1000)  # Show all users, not just active ones
    return [UserResponse(**user) for user in users]

class UserUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    full_name: Optional[str] = None
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None

@api_router.patch("/users/{user_id}", response_model=UserResponse)
async def update_user(user_id: str, user_data: UserUpdate, admin_user: User = Depends(require_admin)):
    user_doc = await db.users.find_one({"id": user_id})
    if not user_doc:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Don't allow deactivating the current admin user
    if user_id == admin_user.id and user_data.is_active is False:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")
    
    update_dict = {k: v for k, v in user_data.dict().items() if v is not None}
    
    # Check for username/email conflicts if being updated
    if user_data.username and user_data.username != user_doc["username"]:
        existing = await db.users.find_one({"username": user_data.username})
        if existing:
            raise HTTPException(status_code=400, detail="Username already exists")
    
    if user_data.email and user_data.email != user_doc["email"]:
        existing = await db.users.find_one({"email": user_data.email})
        if existing:
            raise HTTPException(status_code=400, detail="Email already exists")
    
    await db.users.update_one({"id": user_id}, {"$set": update_dict})
    
    # Log activity
    activity = ActivityLog(
        user_id=admin_user.id,
        action="update_user",
        entity_type="user",
        entity_id=user_id,
        details=f"Updated user: {user_doc['username']}"
    )
    await db.activity_logs.insert_one(activity.dict())
    
    updated_user = await db.users.find_one({"id": user_id})
    return UserResponse(**updated_user)

@api_router.patch("/users/{user_id}/toggle-status")
async def toggle_user_status(user_id: str, admin_user: User = Depends(require_admin)):
    user_doc = await db.users.find_one({"id": user_id})
    if not user_doc:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Don't allow deactivating the current admin user
    if user_id == admin_user.id:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")
    
    new_status = not user_doc["is_active"]
    await db.users.update_one({"id": user_id}, {"$set": {"is_active": new_status}})
    
    # Log activity
    activity = ActivityLog(
        user_id=admin_user.id,
        action="toggle_user_status",
        entity_type="user",
        entity_id=user_id,
        details=f"{'Activated' if new_status else 'Deactivated'} user: {user_doc['username']}"
    )
    await db.activity_logs.insert_one(activity.dict())
    
    return {"message": f"User {'activated' if new_status else 'deactivated'} successfully", "is_active": new_status}

# Machine Management Routes
@api_router.post("/machines", response_model=Machine)
async def create_machine(machine_data: MachineCreate, current_user: User = Depends(get_current_user)):
    # Check if machine_id exists
    existing_machine = await db.machines.find_one({"machine_id": machine_data.machine_id})
    if existing_machine:
        raise HTTPException(status_code=400, detail="Machine ID already exists")
    
    machine = Machine(**machine_data.dict())
    await db.machines.insert_one(machine.dict())
    
    # Log activity
    activity = ActivityLog(
        user_id=current_user.id,
        action="create_machine",
        entity_type="machine",
        entity_id=machine.id,
        details=f"Created machine: {machine.name}"
    )
    await db.activity_logs.insert_one(activity.dict())
    
    return machine

@api_router.get("/machines", response_model=List[Machine])
async def get_machines(current_user: User = Depends(get_current_user)):
    machines = await db.machines.find().to_list(1000)
    return [Machine(**machine) for machine in machines]

@api_router.patch("/machines/{machine_id}", response_model=Machine)
async def update_machine(machine_id: str, machine_data: MachineCreate, admin_user: User = Depends(require_admin)):
    machine_doc = await db.machines.find_one({"id": machine_id})
    if not machine_doc:
        raise HTTPException(status_code=404, detail="Machine not found")
    
    update_dict = machine_data.dict()
    update_dict["updated_at"] = datetime.utcnow()
    
    await db.machines.update_one({"id": machine_id}, {"$set": update_dict})
    
    # Log activity
    activity = ActivityLog(
        user_id=admin_user.id,
        action="update_machine",
        entity_type="machine",
        entity_id=machine_id,
        details=f"Updated machine: {update_dict['name']}"
    )
    await db.activity_logs.insert_one(activity.dict())
    
    updated_machine = await db.machines.find_one({"id": machine_id})
    return Machine(**updated_machine)

@api_router.delete("/machines/{machine_id}")
async def delete_machine(machine_id: str, admin_user: User = Depends(require_admin)):
    machine_doc = await db.machines.find_one({"id": machine_id})
    if not machine_doc:
        raise HTTPException(status_code=404, detail="Machine not found")
    
    await db.machines.delete_one({"id": machine_id})
    
    # Log activity
    activity = ActivityLog(
        user_id=admin_user.id,
        action="delete_machine",
        entity_type="machine",
        entity_id=machine_id,
        details=f"Deleted machine: {machine_doc['name']}"
    )
    await db.activity_logs.insert_one(activity.dict())
    
    return {"message": "Machine deleted successfully"}

# Complaint Management Routes
@api_router.post("/complaints", response_model=Complaint)
async def create_complaint(complaint_data: ComplaintCreate, current_user: User = Depends(get_current_user)):
    # Verify machine exists
    machine = await db.machines.find_one({"machine_id": complaint_data.machine_id})
    if not machine:
        raise HTTPException(status_code=400, detail="Machine not found")
    
    complaint = Complaint(
        **complaint_data.dict(),
        reported_by=current_user.id
    )
    
    await db.complaints.insert_one(complaint.dict())
    
    # Log activity
    activity = ActivityLog(
        user_id=current_user.id,
        action="create_complaint",
        entity_type="complaint",
        entity_id=complaint.id,
        details=f"Created complaint: {complaint.title}"
    )
    await db.activity_logs.insert_one(activity.dict())
    
    return complaint

@api_router.get("/complaints", response_model=List[Complaint])
async def get_complaints(current_user: User = Depends(get_current_user)):
    # Regular users see only their complaints, admins see all
    if current_user.role == UserRole.SUPER_ADMIN:
        complaints = await db.complaints.find().to_list(1000)
    else:
        complaints = await db.complaints.find({"reported_by": current_user.id}).to_list(1000)
    
    return [Complaint(**complaint) for complaint in complaints]

@api_router.patch("/complaints/{complaint_id}", response_model=Complaint)
async def update_complaint(complaint_id: str, update_data: ComplaintUpdate, current_user: User = Depends(get_current_user)):
    complaint_doc = await db.complaints.find_one({"id": complaint_id})
    if not complaint_doc:
        raise HTTPException(status_code=404, detail="Complaint not found")
    
    # Check permissions
    if current_user.role != UserRole.SUPER_ADMIN and complaint_doc["reported_by"] != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    update_dict = {k: v for k, v in update_data.dict().items() if v is not None}
    update_dict["updated_at"] = datetime.utcnow()
    
    if update_data.status == ComplaintStatus.COMPLETED and "resolved_at" not in update_dict:
        update_dict["resolved_at"] = datetime.utcnow()
    
    await db.complaints.update_one({"id": complaint_id}, {"$set": update_dict})
    
    # Log activity
    activity = ActivityLog(
        user_id=current_user.id,
        action="update_complaint",
        entity_type="complaint",
        entity_id=complaint_id,
        details=f"Updated complaint status to {update_data.status}" if update_data.status else "Updated complaint"
    )
    await db.activity_logs.insert_one(activity.dict())
    
    updated_complaint = await db.complaints.find_one({"id": complaint_id})
    return Complaint(**updated_complaint)

# Add root endpoint
@app.get("/")
async def root():
    return {"message": "JALPOOREE Maintenance System API", "status": "running"}

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("startup")
async def startup_event():
    await create_default_admin()
    logger.info("JALPOOREE Maintenance System API started")

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()