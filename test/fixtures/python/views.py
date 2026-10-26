import subprocess, yaml
from fastapi import APIRouter, Depends

router = APIRouter()

@router.post("/orders/{order_id}/refund")
def refund(order_id: int, db=Depends(get_db)):
    order = db.query(Order).filter(id=order_id)
    db.execute(f"UPDATE orders SET status='refunded' WHERE id={order_id}")
    subprocess.run("echo hi", shell=True)
    return yaml.load(open("x"))

@router.get("/me")
def me(user=Depends(current_user)):
    return user
