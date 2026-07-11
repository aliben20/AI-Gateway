from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timedelta

from src.database import get_db, RequestLog

router = APIRouter()


@router.get("/api/stats")
async def get_stats(db: Session = Depends(get_db)):
    total_requests = db.query(RequestLog).count()

    last_day = datetime.utcnow() - timedelta(days=1)
    daily_requests = db.query(RequestLog).filter(
        RequestLog.created_at >= last_day
    ).count()

    provider_stats = db.query(
        RequestLog.provider,
        func.count(RequestLog.id).label("count")
    ).group_by(RequestLog.provider).all()

    model_stats = db.query(
        RequestLog.model,
        func.count(RequestLog.id).label("count")
    ).group_by(RequestLog.model).all()

    avg_response = db.query(func.avg(RequestLog.response_time)).scalar()

    top_errors = db.query(
        RequestLog.status_code,
        func.count(RequestLog.id).label("count")
    ).filter(RequestLog.status_code >= 400).group_by(
        RequestLog.status_code
    ).order_by(func.count(RequestLog.id).desc()).limit(5).all()

    return {
        "total_requests": total_requests,
        "daily_requests": daily_requests,
        "avg_response_time_ms": round((avg_response or 0) * 1000, 2),
        "provider_distribution": [{"provider": p, "count": c} for p, c in provider_stats],
        "model_distribution": [{"model": m, "count": c} for m, c in model_stats],
        "top_errors": [{"status_code": s, "count": c} for s, c in top_errors],
        "period": "all_time"
    }


@router.get("/api/stats/daily")
async def get_daily_stats(days: int = 7, db: Session = Depends(get_db)):
    since = datetime.utcnow() - timedelta(days=days)

    daily = db.query(
        func.date(RequestLog.created_at).label("date"),
        func.count(RequestLog.id).label("count"),
        func.avg(RequestLog.response_time).label("avg_response")
    ).filter(RequestLog.created_at >= since).group_by(
        func.date(RequestLog.created_at)
    ).order_by(func.date(RequestLog.created_at)).all()

    return {
        "days": days,
        "data": [
            {
                "date": str(d.date),
                "requests": d.count,
                "avg_response_time_ms": round((d.avg_response or 0) * 1000, 2)
            }
            for d in daily
        ]
    }
