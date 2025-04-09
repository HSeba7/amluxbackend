from django.contrib.auth import authenticate
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from django.utils.timezone import now
from users.models import ScanRecord

import logging
logger = logging.getLogger(__name__)

class LoginAPIView(APIView):
    def post(self, request, *args, **kwargs):
        device_id = request.data.get('device_id')
        password = request.data.get('password')

        if not device_id or not password:
            logger.warning("Login attempt with missing credentials.")
            return Response(
                {'error': 'Device ID and password are required.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            user = authenticate(request, username=device_id, password=password)

            if user is None:
                logger.warning(f"Failed login attempt for device_id: {device_id}")
                return Response(
                    {'error': 'Invalid credentials.'},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            if not user.is_active:
                logger.warning(f"Login attempt for disabled user: {device_id}")
                return Response(
                    {'error': 'User account is disabled.'},
                    status=status.HTTP_403_FORBIDDEN
                )

            token, created = Token.objects.get_or_create(user=user)

            logger.info(f"User {device_id} logged in successfully.")
            return Response({
                'token': token.key,
                'message': 'Login successful.'
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Unexpected error during login for {device_id}: {str(e)}", exc_info=True)
            return Response(
                {'error': 'An unexpected error occurred. Please try again later.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ProtectedView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"message": f"Hello, {request.user.device_id}, you're authenticated!"})



class SubmitScanAPIView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        card_name = request.data.get('card_name')
        card_surname = request.data.get('card_surname')
        card_control = request.data.get('card_control')

        if not all([card_name, card_surname, card_control]):
            logger.warning(f"Missing scan data from user {user.device_id}")
            return Response(
                {'error': 'card_name, card_surname, and card_control are required.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Simulate control check
        is_valid = card_control == 'VALID123'

        if is_valid:
            scan = ScanRecord.objects.create(
                user=user,
                device_id=user.device_id,
                object_name=user.object_name,
                point_name=user.point_name,
                scan_date=now().date(),
                scan_time=now().time(),
                card_name=card_name,
                card_surname=card_surname,
                is_valid=True
            )
            logger.info(f"Valid scan saved: {scan}")

            return Response({
                'status': 'success',
                'message': 'Card is valid.',
                'data': {
                    'device_id': user.device_id,
                    'object_name': user.object_name,
                    'point_name': user.point_name,
                    'scan_date': str(scan.scan_date),
                    'scan_time': str(scan.scan_time),
                    'card_name': card_name,
                    'card_surname': card_surname
                }
            }, status=status.HTTP_200_OK)

        else:
            logger.warning(f"Invalid card scan attempt by user {user.device_id}")
            return Response({
                'status': 'failed',
                'message': 'Invalid card.'
            }, status=status.HTTP_403_FORBIDDEN)