from fastapi import APIRouter, Response

from app.common.business_error import AppError
from app.common.constants.api_tags import ApiTags
from app.schemas.shared.api_base_response import ApiBaseResponse
from app.schemas.shared.utils_schemas import GlobalStringResponse, StringMessage
from app.services import ServiceResult

router = APIRouter(prefix="/examples", tags=[ApiTags.EXAMPLES])


@router.get("/message", response_model=GlobalStringResponse)
async def get_example_message(
    response: Response,
) -> ApiBaseResponse[StringMessage, AppError]:
    result = ServiceResult[StringMessage, AppError].service_success(
        data=StringMessage(message="Votre route peut retourner une réponse standardisée.")
    )
    return result.to_HTTP_api_base_response(response)
