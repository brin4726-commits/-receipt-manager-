from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional
import uuid
from datetime import datetime, timezone
from passlib.context import CryptContext
import jwt
from jwt.exceptions import InvalidTokenError

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
MONGO_URL = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
client = AsyncIOMotorClient(MONGO_URL)
db = client.receipt_db

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT settings
SECRET_KEY = os.environ.get('JWT_SECRET', 'your-secret-key')
ALGORITHM = "HS256"

# Security
security = HTTPBearer()

# Create the main app
app = FastAPI()
api_router = APIRouter(prefix="/api")

# Models
class UserRegister(BaseModel):
    username: str
    password: str
    store_name: str

class UserLogin(BaseModel):
    username: str
    password: str

class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    store_name: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: User

class ReceiptItem(BaseModel):
    product_name: str
    price: float
    quantity: int = 1

class ReceiptCreate(BaseModel):
    receipt_number: str
    customer_name: str
    customer_phone: str
    customer_address: str
    items: List[ReceiptItem]
    delivery_fee: Optional[float] = 0

class Receipt(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    receipt_number: str
    customer_name: str
    customer_phone: str
    customer_address: str
    store_name: str
    items: List[ReceiptItem]
    delivery_fee: float = 0
    subtotal: float
    total: float
    reviewed: bool = False
    created_by: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    month: int
    year: int

class MonthlyReport(BaseModel):
    month: int
    year: int
    total_receipts: int
    total_items_count: int
    total_amount: float
    total_commission: float
    receipts: List[Receipt]

# Helper functions
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict) -> str:
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    token = credentials.credentials
    payload = decode_token(token)
    username = payload.get("sub")
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )
    user = await db.users.find_one({"username": username}, {"_id": 0, "password_hash": 0})
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    return user

# Auth routes
@api_router.post("/auth/register", response_model=TokenResponse)
async def register(user_data: UserRegister):
    existing_user = await db.users.find_one({"username": user_data.username})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists"
        )
    user_dict = {
        "id": str(uuid.uuid4()),
        "username": user_data.username,
        "password_hash": hash_password(user_data.password),
        "store_name": user_data.store_name,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.users.insert_one(user_dict)
    access_token = create_access_token({"sub": user_data.username})
    user = User(
        id=user_dict["id"],
        username=user_dict["username"],
        store_name=user_dict["store_name"],
        created_at=datetime.now(timezone.utc)
    )
    return TokenResponse(access_token=access_token, user=user)

@api_router.post("/auth/login", response_model=TokenResponse)
async def login(credentials: UserLogin):
    user = await db.users.find_one({"username": credentials.username})
    if not user or not verify_password(credentials.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    access_token = create_access_token({"sub": credentials.username})
    user_obj = User(
        id=user["id"],
        username=user["username"],
        store_name=user["store_name"],
        created_at=datetime.fromisoformat(user["created_at"])
    )
    return TokenResponse(access_token=access_token, user=user_obj)

@api_router.get("/auth/me", response_model=User)
async def get_me(current_user: dict = Depends(get_current_user)):
    return User(**current_user)

# Receipt routes
@api_router.post("/receipts", response_model=Receipt)
async def create_receipt(receipt_data: ReceiptCreate, current_user: dict = Depends(get_current_user)):
    subtotal = sum(item.price * item.quantity for item in receipt_data.items)
    commission = subtotal * 0.01
    total = subtotal + receipt_data.delivery_fee
    now = datetime.now(timezone.utc)
    receipt_dict = {
        "id": str(uuid.uuid4()),
        "receipt_number": receipt_data.receipt_number,
        "customer_name": receipt_data.customer_name,
        "customer_phone": receipt_data.customer_phone,
        "customer_address": receipt_data.customer_address,
        "store_name": current_user["store_name"],
        "items": [item.model_dump() for item in receipt_data.items],
        "subtotal": subtotal,
        "total": total,
        "commission_1percent": commission,
        "reviewed": False,
        "created_by": current_user["username"],
        "created_at": now.isoformat(),
        "month": now.month,
        "year": now.year
    }
    await db.receipts.insert_one(receipt_dict)
    receipt_dict["created_at"] = now
    return Receipt(**receipt_dict)

@api_router.get("/receipts", response_model=List[Receipt])
async def get_receipts(current_user: dict = Depends(get_current_user)):
    receipts = await db.receipts.find(
        {"created_by": current_user["username"]},
        {"_id": 0}
    ).sort("created_at", -1).to_list(1000)
    for receipt in receipts:
        if isinstance(receipt['created_at'], str):
            receipt['created_at'] = datetime.fromisoformat(receipt['created_at'])
    return receipts

@api_router.get("/receipts/{receipt_id}", response_model=Receipt)
async def get_receipt(receipt_id: str, current_user: dict = Depends(get_current_user)):
    receipt = await db.receipts.find_one(
        {"id": receipt_id, "created_by": current_user["username"]},
        {"_id": 0}
    )
    if not receipt:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Receipt not found"
        )
    if isinstance(receipt['created_at'], str):
        receipt['created_at'] = datetime.fromisoformat(receipt['created_at'])
    return Receipt(**receipt)

@api_router.put("/receipts/{receipt_id}", response_model=Receipt)
async def update_receipt(receipt_id: str, receipt_data: ReceiptCreate, current_user: dict = Depends(get_current_user)):
    existing_receipt = await db.receipts.find_one(
        {"id": receipt_id, "created_by": current_user["username"]}
    )
    if not existing_receipt:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Receipt not found"
        )
    subtotal = sum(item.price * item.quantity for item in receipt_data.items)
    commission = subtotal * 0.01
    total = subtotal + receipt_data.delivery_fee
    update_dict = {
        "receipt_number": receipt_data.receipt_number,
        "customer_name": receipt_data.customer_name,
        "customer_phone": receipt_data.customer_phone,
        "customer_address": receipt_data.customer_address,
        "items": [item.model_dump() for item in receipt_data.items],
        "subtotal": subtotal,
        "total": total,
        "commission_1percent": commission
    }
    await db.receipts.update_one(
        {"id": receipt_id, "created_by": current_user["username"]},
        {"$set": update_dict}
    )
    updated_receipt = await db.receipts.find_one(
        {"id": receipt_id, "created_by": current_user["username"]},
        {"_id": 0}
    )
    if isinstance(updated_receipt['created_at'], str):
        updated_receipt['created_at'] = datetime.fromisoformat(updated_receipt['created_at'])
    return Receipt(**updated_receipt)

@api_router.put("/receipts/{receipt_id}/review")
async def review_receipt(receipt_id: str, current_user: dict = Depends(get_current_user)):
    result = await db.receipts.update_one(
        {"id": receipt_id, "created_by": current_user["username"]},
        {"$set": {"reviewed": True}}
    )
    if result.matched_count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Receipt not found"
        )
    return {"message": "Receipt reviewed successfully"}

@api_router.delete("/receipts/{receipt_id}")
async def delete_receipt(receipt_id: str, current_user: dict = Depends(get_current_user)):
    result = await db.receipts.delete_one(
        {"id": receipt_id, "created_by": current_user["username"]}
    )
    if result.deleted_count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Receipt not found"
        )
    return {"message": "Receipt deleted successfully"}

@api_router.get("/reports/monthly", response_model=MonthlyReport)
async def get_monthly_report(month: int, year: int, current_user: dict = Depends(get_current_user)):
    receipts = await db.receipts.find(
        {
            "created_by": current_user["username"],
            "month": month,
            "year": year
        },
        {"_id": 0}
    ).to_list(1000)
    for receipt in receipts:
        if isinstance(receipt['created_at'], str):
            receipt['created_at'] = datetime.fromisoformat(receipt['created_at'])
    total_items_count = sum(
        sum(item["quantity"] for item in receipt["items"])
        for receipt in receipts
    )
    total_amount = sum(receipt["total"] for receipt in receipts)
    total_commission = sum(receipt["commission_1percent"] for receipt in receipts)
    return MonthlyReport(
        month=month,
        year=year,
        total_receipts=len(receipts),
        total_items_count=total_items_count,
        total_amount=total_amount,
        total_commission=total_commission,
        receipts=[Receipt(**r) for r in receipts]
    )

# Include router
app.include_router(api_router)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*']
)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
