from django.contrib.auth import authenticate
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from django.utils.timezone import now
from users.models import ScanRecord, DeviceUser

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
        card_response = request.data.get('card_response')  

        if not all([card_name, card_surname, card_control]):
            logger.warning(f"Missing scan data from user {user.device_id}")
            return Response(
                {'error': 'card_name, card_surname, and card_control are required.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Save the scan record
        scan = ScanRecord.objects.create(
            user=user,
            object_name=user.object_name.name if user.object_name else None,
            point_name=user.point_name,
            scan_date=now().date(),
            scan_time=now().time(),
            card_name=card_name,
            card_surname=card_surname,
            card_response=card_response,  
            is_valid=True  
        )
        logger.info(f"Scan saved: {scan}")

        return Response({
            'status': 'success',
            'message': 'Scan data saved successfully.',
            'data': {
                'device_id': user.device_id,
                'object_name': user.object_name.name if user.object_name else None,
                'point_name': user.point_name,
                'scan_date': str(scan.scan_date),
                'scan_time': str(scan.scan_time),
                'card_name': card_name,
                'card_surname': card_surname,
                'card_control': card_control,
                'card_response': card_response  # Include card_response in the response
            }
        }, status=status.HTTP_200_OK)
        

class GetDetails(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            # Fetch user details from DeviceUser model
            user = DeviceUser.objects.get(device_id=request.user.device_id)

            scan_record = ScanRecord.objects.filter(user=user).order_by('-scan_date', '-scan_time').first()

            # Prepare the response data
            data = {
                'device_id': user.device_id,
                'object_name': user.object_name.name if user.object_name else None,
                'point_name': user.point_name,
                'created_at': user.object_name.created_at if user.object_name else None,
                'scan_date': scan_record.scan_date if scan_record else None,
                'scan_time': scan_record.scan_time if scan_record else None,
                'card_name': scan_record.card_name if scan_record else None,
                'card_surname': scan_record.card_surname if scan_record else None,
                'card_response': scan_record.card_response if scan_record else None,
                'is_valid': scan_record.is_valid if scan_record else None,
            }

            return Response(data, status=status.HTTP_200_OK)

        except DeviceUser.DoesNotExist:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Error fetching user details: {str(e)}", exc_info=True)
            return Response({'error': 'An unexpected error occurred.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)