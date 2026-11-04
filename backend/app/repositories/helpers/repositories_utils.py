import logging

from fastapi import status

from app.common.business_error import AppError, AppErrorType
from app.common.constants.messages import Messages
from app.repositories import CrudResult


class RepositoriesUtils:
    @staticmethod
    def handle_unexpected_error(
        exception: Exception, logger: logging.Logger
    ) -> CrudResult[None, AppError]:
        logger.exception(
            "Unhandled repository error: %s",
            exception,
            exc_info=exception,
        )
        return CrudResult.crud_failure(
            error=AppError(
                error_type=AppErrorType.UNKNOWN_ERROR,
                error_message=Messages.INTERNAL_SERVER_ERROR,
            ),
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
