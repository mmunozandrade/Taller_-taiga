# main_mediterraneo.py
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Dict
from uuid import UUID, uuid4
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import random

# --- Seguridad ---
from passlib.context import CryptContext
from jose import JWTError, jwt

# ===============================
# 0) Configuración general
# ===============================
APP_TITLE = "API Mediterraneo"
API_PREFIX = "/api/mediterraneo"

SECRET_KEY = "clave-super-secreta-mediterraneo"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 45

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{API_PREFIX}/auth/login")

# ===============================
# 1) Modelos base / Response
# ===============================
class Response(BaseModel):
    statusCode: int = 200
    message: str = "OK"
    data: Optional[dict | list] = None

# ===============================
# 2) Entidades según el diagrama
# ===============================
# USER
class User(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    email: EmailStr
    passwordHash: str
    createdAt: datetime = Field(default_factory=datetime.now)

# INPUT_REGISTRATION (para registro social)
class InputRegistration(BaseModel):
    provider: str          # "google" | "facebook"
    oauthToken: str

# TWO_FACTOR
class TwoFactor(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    userId: UUID
    secret: str
    method: str            # "sms" | "totp"
    verifiedAt: Optional[datetime] = None

# ENCRYPTION_KEY (metadatos de cifrado)
class EncryptionKey(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    algorithm: str
    keyId: str
    scope: str

# PRODUCT (necesario para CartItem)
class Product(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    name: str
    price: Decimal
    category: Optional[str] = None
    stock: Optional[int] = 100

# CART & CART ITEM
class CartItem(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    productId: UUID
    quantity: int

class Cart(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    userId: UUID
    items: List[CartItem] = []
    total: Decimal = Decimal("0.00")
    status: str = "Activo"  # Activo | Cerrado

# ORDER
class Order(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    code: str
    userId: UUID
    total: Decimal
    status: str = "Recibido"    # Recibido | Pagado | EnCamino | Entregado
    confirmedAt: Optional[datetime] = None

# COUPON
class Coupon(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    code: str
    discountPct: int
    expiresAt: datetime
    redeemedBy: Optional[UUID] = None

# PAYMENT
class Payment(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    method: str            # "card" | "wallet"
    amount: Decimal
    status: str            # "approved" | "rejected" | "pending"
    authorizationCode: Optional[str] = None

# INVOICE
class Invoice(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    number: str
    total: Decimal
    pdfUrl: str
    customerEmail: EmailStr

# ASSIGNMENT
class Assignment(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    orderId: UUID
    driverId: UUID
    assignedDate: datetime = Field(default_factory=datetime.now)
    status: str = "asignado"     # asignado | en_retiro | entregado

# TRACKING
class Tracking(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    orderId: UUID
    lat: Decimal
    lng: Decimal
    updatedAt: datetime = Field(default_factory=datetime.now)

# STOCK_ALERT
class StockAlert(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    productId: UUID
    threshold: int
    currentQuantity: int

# CONSUMPTION_REPORT
class ConsumptionReport(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    period: str           # "2025-W45", "2025-10"
    totalOrders: int
    topProductId: Optional[UUID] = None

# PROMOTION
class Promotion(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    title: str
    discountPct: int
    segment: str

# INPUT_DATA (para cifrado de datos de ejemplo)
class InputData(BaseModel):
    plainText: str
    algorithm: str

# ===============================
# 3) DTOs de entrada
# ===============================
class RegisterEmailInput(BaseModel):
    email: EmailStr
    password: str

class RegisterSocialInput(InputRegistration): ...
class LoginInput(BaseModel):
    email: EmailStr
    password: str

class TwoFactorEnableInput(BaseModel):
    method: str  # "sms" | "totp"

class TwoFactorVerifyInput(BaseModel):
    userId: UUID
    code: str

class CartAddItemInput(BaseModel):
    productId: UUID
    quantity: int = Field(ge=1)

class CartUpdateQtyInput(BaseModel):
    itemId: UUID
    quantity: int = Field(ge=1)

class ConfirmOrderInput(BaseModel):
    couponCode: Optional[str] = None

class CardPaymentInput(BaseModel):
    orderId: UUID
    amount: Decimal
    cardToken: str

class WalletPaymentInput(BaseModel):
    orderId: UUID
    amount: Decimal
    provider: str  # "paypal" | "mercadopago"
    walletToken: str

class SendInvoiceInput(BaseModel):
    invoiceId: UUID
    email: EmailStr

class AssignDriverInput(BaseModel):
    orderId: UUID

class TrackOrderQuery(BaseModel):
    orderId: UUID

class StockAlertInput(BaseModel):
    productId: UUID
    threshold: int
    currentQuantity: int

class ReportQuery(BaseModel):
    period: str  # "2025-W45"

class PromotionInput(BaseModel):
    title: str
    discountPct: int
    segment: str

class RedeemCouponInput(BaseModel):
    code: str

# ===============================
# 4) Utilidades de seguridad
# ===============================
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    exc = HTTPException(status_code=401, detail="Token inválido", headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise exc
    except JWTError:
        raise exc
    user = next((u for u in db_users if u.email == email), None)
    if not user:
        raise exc
    return user

# ===============================
# 5) "Base de datos" en memoria
# ===============================
db_users: List[User] = []
db_twofa: List[TwoFactor] = []
db_keys: List[EncryptionKey] = [EncryptionKey(algorithm="AES-256", keyId="k1", scope="user-data")]
db_products: List[Product] = [
    Product(name="Shawarma", price=Decimal("5.50"), category="Wrap"),
    Product(name="Falafel", price=Decimal("4.00"), category="Vegano"),
    Product(name="Hummus", price=Decimal("3.00"), category="Dip"),
]
db_carts: List[Cart] = []
db_orders: List[Order] = []
db_coupons: List[Coupon] = [
    Coupon(code="MED10", discountPct=10, expiresAt=datetime.now() + timedelta(days=30)),
]
db_payments: List[Payment] = []
db_invoices: List[Invoice] = []
db_assignments: List[Assignment] = []
db_trackings: List[Tracking] = []
db_stock_alerts: List[StockAlert] = []
db_reports: List[ConsumptionReport] = []
db_promotions: List[Promotion] = []

def get_cart_by_user(user_id: UUID) -> Cart:
    cart = next((c for c in db_carts if c.userId == user_id and c.status == "Activo"), None)
    if not cart:
        cart = Cart(userId=user_id)
        db_carts.append(cart)
    return cart

def recalc_cart_total(cart: Cart) -> None:
    total = Decimal("0.00")
    for it in cart.items:
        prod = next((p for p in db_products if p.id == it.productId), None)
        if prod:
            total += prod.price * it.quantity
    cart.total = total.quantize(Decimal("0.01"))

# ===============================
# 6) App
# ===============================
app = FastAPI(title=APP_TITLE, version="1.0.0", description="Backend Mediterraneo basado en historias y diagrama.")

@app.get("/")
def root():
    return {"message": f"{APP_TITLE} OK. Ir a /docs."}

# ===============================
# 7) Auth & Seguridad (US-01, US-02, US-15, US-16)
# ===============================
@app.post(f"{API_PREFIX}/auth/register-email", response_model=User, tags=["Auth"])
def register_email(input: RegisterEmailInput):
    if next((u for u in db_users if u.email == input.email), None):
        raise HTTPException(status_code=400, detail="Correo ya existente")
    if len(input.password) < 8:
        raise HTTPException(status_code=400, detail="La contraseña debe tener mínimo 8 caracteres")
    user = User(email=input.email, passwordHash=hash_password(input.password))
    db_users.append(user)
    return user

@app.post(f"{API_PREFIX}/auth/register-social", response_model=User, tags=["Auth"])
def register_social(input: RegisterSocialInput):
    # Simulación de verificación de oauthToken
    if not input.oauthToken or input.provider.lower() not in {"google", "facebook"}:
        raise HTTPException(status_code=400, detail="Proveedor o token inválido")
    email = f"user_{random.randint(1000,9999)}@{input.provider}.mock"
    if next((u for u in db_users if u.email == email), None):
        raise HTTPException(status_code=400, detail="Correo ya existente")
    user = User(email=email, passwordHash=hash_password("oauth!dummy"))
    db_users.append(user)
    return user

@app.post(f"{API_PREFIX}/auth/login", tags=["Auth"])
def login(form: OAuth2PasswordRequestForm = Depends()):
    user = next((u for u in db_users if u.email == form.username), None)
    if not user or not verify_password(form.password, user.passwordHash):
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    token = create_access_token({"sub": user.email})
    return {"access_token": token, "token_type": "bearer"}

@app.post(f"{API_PREFIX}/auth/2fa/enable", response_model=TwoFactor, tags=["Auth"])
def enable_2fa(input: TwoFactorEnableInput, current: User = Depends(get_current_user)):
    tf = TwoFactor(userId=current.id, secret=f"sec_{random.randint(100000,999999)}", method=input.method)
    db_twofa.append(tf)
    return tf

@app.post(f"{API_PREFIX}/auth/2fa/verify", response_model=Response, tags=["Auth"])
def verify_2fa(input: TwoFactorVerifyInput):
    tf = next((x for x in db_twofa if x.userId == input.userId), None)
    if not tf:
        raise HTTPException(status_code=404, detail="2FA no configurado")
    # Simulación: cualquier code de 6 dígitos funciona
    if len(input.code) == 6 and input.code.isdigit():
        tf.verifiedAt = datetime.now()
        return Response(message="2FA verificado")
    raise HTTPException(status_code=400, detail="Código inválido")

@app.post(f"{API_PREFIX}/security/encrypt", response_model=Response, tags=["Security"])
def encrypt_data(input: InputData, current: User = Depends(get_current_user)):
    key = db_keys[0]
    # Simulación de cifrado
    cipher = f"{input.algorithm}:{key.keyId}:{input.plainText[::-1]}"
    return Response(message="Dato cifrado", data={"cipher": cipher})

# ===============================
# 8) Carrito & Pedido (US-03, US-04)
# ===============================
@app.get(f"{API_PREFIX}/products", response_model=List[Product], tags=["Catalog"])
def list_products():
    return db_products

@app.post(f"{API_PREFIX}/cart/add", response_model=Cart, tags=["Cart"])
def cart_add(input: CartAddItemInput, current: User = Depends(get_current_user)):
    prod = next((p for p in db_products if p.id == input.productId), None)
    if not prod:
        raise HTTPException(status_code=404, detail="Producto no encontrado")
    cart = get_cart_by_user(current.id)
    # Buscar si ya existe el ítem
    item = next((i for i in cart.items if i.productId == input.productId), None)
    if item:
        item.quantity += input.quantity
    else:
        cart.items.append(CartItem(productId=input.productId, quantity=input.quantity))
    recalc_cart_total(cart)
    return cart

@app.put(f"{API_PREFIX}/cart/update", response_model=Cart, tags=["Cart"])
def cart_update(input: CartUpdateQtyInput, current: User = Depends(get_current_user)):
    cart = get_cart_by_user(current.id)
    item = next((i for i in cart.items if i.id == input.itemId), None)
    if not item:
        raise HTTPException(status_code=404, detail="Item no encontrado")
    item.quantity = input.quantity
    recalc_cart_total(cart)
    return cart

@app.get(f"{API_PREFIX}/cart", response_model=Cart, tags=["Cart"])
def cart_view(current: User = Depends(get_current_user)):
    return get_cart_by_user(current.id)

@app.post(f"{API_PREFIX}/orders/confirm", response_model=Order, tags=["Orders"])
def confirm_order(input: ConfirmOrderInput, current: User = Depends(get_current_user)):
    cart = get_cart_by_user(current.id)
    if not cart.items:
        raise HTTPException(status_code=400, detail="Carrito vacío")
    # Cupón (opcional)
    total = cart.total
    if input.couponCode:
        c = next((x for x in db_coupons if x.code == input.couponCode and x.expiresAt > datetime.now()), None)
        if not c:
            raise HTTPException(status_code=400, detail="Cupón inválido o expirado")
        if c.redeemedBy and c.redeemedBy != current.id:
            raise HTTPException(status_code=400, detail="Cupón ya usado")
        total = (total * Decimal(100 - c.discountPct) / Decimal(100)).quantize(Decimal("0.01"))
        c.redeemedBy = current.id

    order = Order(code=f"MED-{random.randint(10000,99999)}", userId=current.id, total=total,
                  status="Recibido", confirmedAt=datetime.now())
    db_orders.append(order)
    cart.status = "Cerrado"
    return order

# ===============================
# 9) Pagos (US-05, US-06)
# ===============================
@app.post(f"{API_PREFIX}/payments/card", response_model=Response, tags=["Payments"])
def pay_card(input: CardPaymentInput, current: User = Depends(get_current_user)):
    order = next((o for o in db_orders if o.id == input.orderId and o.userId == current.id), None)
    if not order:
        raise HTTPException(status_code=404, detail="Orden no encontrada")
    if input.amount != order.total:
        raise HTTPException(status_code=400, detail="Monto no coincide con el total")
    auth = f"AUTH{random.randint(1000,9999)}"
    payment = Payment(method="card", amount=input.amount, status="approved", authorizationCode=auth)
    db_payments.append(payment)
    order.status = "Pagado"
    return Response(message="Pago aprobado", data={"authorizationCode": auth})

@app.post(f"{API_PREFIX}/payments/wallet", response_model=Response, tags=["Payments"])
def pay_wallet(input: WalletPaymentInput, current: User = Depends(get_current_user)):
    order = next((o for o in db_orders if o.id == input.orderId and o.userId == current.id), None)
    if not order:
        raise HTTPException(status_code=404, detail="Orden no encontrada")
    if input.amount != order.total:
        raise HTTPException(status_code=400, detail="Monto no coincide con el total")
    status = "approved"
    payment = Payment(method=f"wallet:{input.provider}", amount=input.amount, status=status,
                      authorizationCode=f"WAL{random.randint(1000,9999)}")
    db_payments.append(payment)
    order.status = "Pagado"
    return Response(message="Pago aprobado", data={"provider": input.provider, "status": status})

# ===============================
# 10) Boletas (US-07, US-08)
# ===============================
@app.post(f"{API_PREFIX}/invoices/generate", response_model=Invoice, tags=["Invoices"])
def generate_invoice(orderId: UUID, current: User = Depends(get_current_user)):
    order = next((o for o in db_orders if o.id == orderId and o.userId == current.id), None)
    if not order:
        raise HTTPException(status_code=404, detail="Orden no encontrada")
    if order.status != "Pagado":
        raise HTTPException(status_code=400, detail="La orden debe estar pagada")
    invoice = Invoice(
        number=f"B-{random.randint(1000,9999)}",
        total=order.total,
        pdfUrl=f"https://storage.example.com/boletas/{uuid4()}.pdf",
        customerEmail=current.email
    )
    db_invoices.append(invoice)
    return invoice

@app.post(f"{API_PREFIX}/invoices/send", response_model=Response, tags=["Invoices"])
def send_invoice(input: SendInvoiceInput):
    inv = next((i for i in db_invoices if i.id == input.invoiceId), None)
    if not inv:
        raise HTTPException(status_code=404, detail="Boleta no encontrada")
    return Response(message=f"Boleta enviada a {input.email}")

# ===============================
# 11) Reparto & Tracking (US-09, US-10)
# ===============================
@app.post(f"{API_PREFIX}/delivery/assign", response_model=Assignment, tags=["Delivery"])
def assign_driver(input: AssignDriverInput):
    order = next((o for o in db_orders if o.id == input.orderId), None)
    if not order:
        raise HTTPException(status_code=404, detail="Orden no encontrada")
    asg = Assignment(orderId=order.id, driverId=uuid4(), status="asignado")
    db_assignments.append(asg)
    return asg

@app.get(f"{API_PREFIX}/delivery/tracking", response_model=Tracking, tags=["Delivery"])
def get_tracking(orderId: UUID):
    trk = Tracking(
        orderId=orderId,
        lat=Decimal("-33.45") + Decimal(random.uniform(-0.01, 0.01)),
        lng=Decimal("-70.67") + Decimal(random.uniform(-0.01, 0.01)),
    )
    db_trackings.append(trk)
    return trk

# ===============================
# 12) Inventario (US-11, US-12)
# ===============================
@app.post(f"{API_PREFIX}/inventory/stock-alert", response_model=StockAlert, tags=["Inventory"])
def create_stock_alert(input: StockAlertInput):
    alert = StockAlert(**input.model_dump())
    db_stock_alerts.append(alert)
    return alert

@app.post(f"{API_PREFIX}/inventory/report", response_model=ConsumptionReport, tags=["Inventory"])
def generate_report(input: ReportQuery):
    # Simulación: top product aleatorio
    top = random.choice(db_products).id if db_products else None
    rpt = ConsumptionReport(period=input.period, totalOrders=len(db_orders), topProductId=top)
    db_reports.append(rpt)
    return rpt

# ===============================
# 13) Marketing (US-13, US-14)
# ===============================
@app.post(f"{API_PREFIX}/marketing/promotion", response_model=Promotion, tags=["Marketing"])
def send_promotion(input: PromotionInput):
    promo = Promotion(**input.model_dump())
    db_promotions.append(promo)
    # Simular envío a segmentos
    return promo

@app.post(f"{API_PREFIX}/marketing/coupon/redeem", response_model=Response, tags=["Marketing"])
def redeem_coupon(input: RedeemCouponInput, current: User = Depends(get_current_user)):
    c = next((x for x in db_coupons if x.code == input.code and x.expiresAt > datetime.now()), None)
    if not c:
        raise HTTPException(status_code=400, detail="Cupón inválido o expirado")
    if c.redeemedBy and c.redeemedBy != current.id:
        raise HTTPException(status_code=400, detail="Cupón ya usado")
    c.redeemedBy = current.id
    return Response(message="Cupón canjeado")