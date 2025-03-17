from datetime import datetime, timezone
from typing import cast
from uuid import uuid4

from fastapi import APIRouter, Depends, status, HTTPException
from pydantic_settings import BaseSettings
from sqlalchemy import select, delete, update
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload
from starlette.status import HTTP_409_CONFLICT

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from schemas.accounts import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    UserLoginRequestSchema,
    TokenRefreshRequestSchema, UserActivationRequestSchema, PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema, MessageResponseSchema, UserLoginResponseSchema, TokenRefreshResponseSchema
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password
from security.token_manager import JWTAuthManager

router = APIRouter()


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
async def register_user(user_data: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(UserModel).where(UserModel.email == user_data.email))
    existing_user = result.scalars().first()

    if existing_user:
        raise HTTPException(status_code=409, detail=f"A user with this email {user_data.email} already exists.")

    user_group_result = await db.execute(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    )
    user_group = user_group_result.scalars().first()

    if not user_group:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="User group not found.")

    hashed_password = hash_password(user_data.password)

    try:
        new_user = UserModel(email=user_data.email, _hashed_password=hashed_password, group_id=user_group.id)
        db.add(new_user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=new_user.id)
        db.add(activation_token)

        await db.commit()
        return UserRegistrationResponseSchema(id=new_user.id, email=new_user.email)

    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=HTTP_409_CONFLICT, detail="A user with this email already exists.")

    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post("/activate/", status_code=status.HTTP_200_OK)
async def activate_user_account(
    payload: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    email = payload.email
    token = payload.token

    result = await db.execute(select(ActivationTokenModel).where(ActivationTokenModel.token == token))
    activation_token = result.scalars().first()

    if not activation_token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Invalid or expired activation token.")

    result = await db.execute(select(UserModel).where(UserModel.email == email))
    user = result.scalars().first()

    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="User not found.")

    if user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="User account is already active.")

    if activation_token.user_id != user.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Invalid or expired activation token.")

    if cast(datetime, activation_token.expires_at).replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Invalid or expired activation token.")

    await db.execute(update(UserModel).where(UserModel.id == user.id).values(is_active=True))
    await db.commit()

    await db.execute(delete(ActivationTokenModel).where(ActivationTokenModel.token == token))
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", status_code=status.HTTP_200_OK)
async def request_password_reset_token(
    payload: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    email = payload.email
    result = await db.execute(select(UserModel).where(UserModel.email == email))
    user = result.scalars().first()

    if not user or not user.is_active:
        return {"message": "If you are registered, you will receive an email with instructions."}

    await db.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id))
    await db.commit()

    reset_token = str(uuid4())
    reset_token_model = PasswordResetTokenModel(user_id=user.id, token=reset_token)

    db.add(reset_token_model)
    await db.commit()

    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def password_reset_complete(
        request_data: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    try:
        stmt_user = select(UserModel).where(
            UserModel.email == request_data.email
        )
        result_user = await db.execute(stmt_user)
        user = result_user.scalars().first()

        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        stmt_token = select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id,
            PasswordResetTokenModel.token == request_data.token
        )
        result_token = await db.execute(stmt_token)
        reset_token = result_token.scalars().first()

        stmt_existing_tokens = select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id
        )
        result_existing_tokens = await db.execute(stmt_existing_tokens)
        existing_tokens = result_existing_tokens.scalars().all()

        current_time = datetime.now(timezone.utc)
        if not reset_token:
            if existing_tokens:
                await db.execute(
                    delete(PasswordResetTokenModel).where(
                        PasswordResetTokenModel.user_id == user.id
                    )
                )
                await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        expires_at = reset_token.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if expires_at < current_time:
            await db.execute(
                delete(PasswordResetTokenModel).where(
                    PasswordResetTokenModel.user_id == user.id
                )
            )
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        user.password = request_data.password
        await db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.id == reset_token.id
            )
        )
        await db.commit()

        return MessageResponseSchema(message="Password reset successfully.")

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def login_user(
        request_data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseSettings = Depends(get_settings),
):
    try:
        stmt_user = select(UserModel).where(
            UserModel.email == request_data.email
        )
        result_user = await db.execute(stmt_user)
        user = result_user.scalars().first()

        if not user or not user.verify_password(request_data.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password."
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is not activated."
            )

        access_token = jwt_manager.create_access_token(
            data={"user_id": user.id}
        )
        refresh_token = jwt_manager.create_refresh_token(
            data={"user_id": user.id}
        )

        refresh_token_record = RefreshTokenModel.create(
            user_id=user.id,
            token=refresh_token,
            days_valid=settings.LOGIN_TIME_DAYS,
        )
        db.add(refresh_token_record)
        await db.commit()

        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer"
        )

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def refresh_user(
        request_data: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManager = Depends(get_jwt_auth_manager),
):
    try:
        decoded_token = jwt_manager.decode_refresh_token(
            request_data.refresh_token
        )
    except BaseSecurityError:
        raise HTTPException(status_code=400, detail="Token has expired.")

    refresh_token = await db.execute(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == request_data.refresh_token
        )
    )
    refresh_token = refresh_token.scalar_one_or_none()

    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user = await db.execute(
        select(UserModel).where(UserModel.id == decoded_token.get("user_id"))
    )
    user = user.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    access_token = jwt_manager.create_access_token(
        data={"user_id": decoded_token.get("user_id")}
    )

    return TokenRefreshResponseSchema(access_token=access_token)
