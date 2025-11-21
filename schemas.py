"""
Database Schemas for Travel Website

Each Pydantic model maps to a MongoDB collection (lowercased class name).
"""
from typing import List, Optional
from pydantic import BaseModel, Field, EmailStr
from datetime import datetime


class AdminUser(BaseModel):
    email: EmailStr
    name: str = Field(..., max_length=120)
    password_hash: str
    role: str = Field("admin", description="role name")
    failed_attempts: int = 0
    locked_until: Optional[datetime] = None


class Service(BaseModel):
    title: str
    slug: str
    description: str
    icon: Optional[str] = None
    content: Optional[str] = None
    featured: bool = False
    order: int = 0


class Offer(BaseModel):
    title: str
    image_url: str
    description: Optional[str] = None
    expires_at: datetime
    active: bool = True


class Testimonial(BaseModel):
    name: str
    avatar_url: Optional[str] = None
    rating: int = Field(ge=1, le=5)
    quote: str
    company: Optional[str] = None


class Package(BaseModel):
    title: str
    slug: str
    image_url: str
    price: float
    currency: str = "AED"
    highlights: List[str] = []
    icons: List[str] = []
    duration: Optional[str] = None


class BlogPost(BaseModel):
    title: str
    slug: str
    excerpt: str
    content: str
    image_url: Optional[str] = None
    published: bool = True
    published_at: Optional[datetime] = None


class ContactSubmission(BaseModel):
    full_name: str
    phone: str
    email: EmailStr
    message: str
    ip: Optional[str] = None
    user_agent: Optional[str] = None


class AuditLog(BaseModel):
    email: Optional[EmailStr] = None
    ip: Optional[str] = None
    user_agent: Optional[str] = None
    action: str
    success: bool = True
    details: Optional[str] = None

