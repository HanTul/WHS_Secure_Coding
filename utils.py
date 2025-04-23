from datetime import datetime


def time_ago(dt):
    delta = datetime.utcnow() - dt
    sec = int(delta.total_seconds())
    if sec < 60:
        return f"{sec}초 전"
    if sec < 3600:
        return f"{sec//60}분 전"
    if sec < 86400:
        return f"{sec//3600}시간 전"
    return f"{sec//86400}일 전"


def make_room_id(buyer_id, seller_id, product_id):
    return f"dm-{min(buyer_id, seller_id)}-{max(buyer_id, seller_id)}-{product_id}"
