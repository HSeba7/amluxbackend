from django.contrib.auth import authenticate
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from django.utils.timezone import now
from users.models import ScanRecord, DeviceUser, ClockInAndOut
from datetime import timedelta
from django.db.models import Q

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
                'user_id': user.id,
                'device_id': user.device_id,
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


class GetDetails(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            user = DeviceUser.objects.get(device_id=request.user.device_id)

            scan_record = ScanRecord.objects.filter(user=user).order_by('-scan_date', '-scan_time').first()

            data = {
                'scan_id': scan_record.id if scan_record else None,
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
        

class SubmitScanAPIView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        card_name = request.data.get('card_name')
        card_surname = request.data.get('card_surname')
        card_control = request.data.get('card_control')
        card_response = request.data.get('card_response')
        card_object_name = request.data.get('object_name')  

        if not all([card_name, card_surname, card_control, card_object_name]):
            logger.warning(f"Missing scan data from user {user.device_id}")
            return Response(
                {'error': 'card_name, card_surname, card_control, and object_name are required.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        last_scan = ScanRecord.objects.filter(user=user).order_by('-scan_date', '-scan_time').first()
        if last_scan:
            time_since_last_scan = now() - timedelta(seconds=10)
            if last_scan.scan_date == now().date() and last_scan.scan_time > time_since_last_scan.time():
                last_scan_time = timedelta(
                    hours=last_scan.scan_time.hour,
                    minutes=last_scan.scan_time.minute,
                    seconds=last_scan.scan_time.second
                )
                current_time = timedelta(
                    hours=now().time().hour,
                    minutes=now().time().minute,
                    seconds=now().time().second
                )
                remaining_time = (last_scan_time + timedelta(seconds=10)) - current_time
                remaining_seconds = int(remaining_time.total_seconds())

                logger.warning(f"User {user.device_id} attempted to scan too soon after the last scan.")
                return Response(
                    {
                        'error': f'You can only scan after {remaining_seconds} seconds from your last successful scan.',
                    },
                    status=status.HTTP_429_TOO_MANY_REQUESTS
                )

        is_valid = card_object_name == (user.object_name.name if user.object_name else None)

        if not is_valid:
            logger.warning(f"Invalid scan attempt by user {user.device_id}. Object name mismatch.")
            return Response(
                {'error': 'Invalid scan. Object name on card does not match the device object name.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        scan = ScanRecord.objects.create(
            user=user,
            object_name=user.object_name.name if user.object_name else None,
            point_name=user.point_name,
            scan_date=now().date(),
            scan_time=now().time(),
            card_name=card_name,
            card_surname=card_surname,
            card_response=card_response,
            is_valid=is_valid  
        )
        logger.info(f"Scan saved: {scan}")

        return Response({
            'status': 'success',
            'message': 'Scan data saved successfully.',
            'data': {
                'scan_id': scan.id,
                'device_id': user.device_id,
                'object_name': user.object_name.name if user.object_name else None,
                'point_name': user.point_name,
                'scan_date': str(scan.scan_date),
                'scan_time': str(scan.scan_time),
                'card_name': card_name,
                'card_surname': card_surname,
                'card_control': card_control,
                'card_response': card_response,
                'is_valid': is_valid  
            }
        }, status=status.HTTP_200_OK)
        
class GetAllScanRecordsAPIView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            scan_id = request.query_params.get('scan_id')

            if scan_id:
                try:
                    record = ScanRecord.objects.get(id=scan_id)
                    data = {
                        'scan_id': record.id,
                        'device_id': record.user.device_id,
                        'object_name': record.user.object_name.name if record.user.object_name else None,
                        'point_name': record.user.point_name,
                        'scan_date': str(record.scan_date),
                        'scan_time': str(record.scan_time),
                        'card_name': record.card_name,
                        'card_surname': record.card_surname,
                        'card_response': record.card_response,
                        'is_valid': record.is_valid,
                    }
                    return Response({'scan_record': data}, status=status.HTTP_200_OK)
                except ScanRecord.DoesNotExist:
                    return Response({'error': 'Scan record not found.'}, status=status.HTTP_404_NOT_FOUND)

            scan_records = ScanRecord.objects.all().order_by('-scan_date', '-scan_time')

            data = []
            for record in scan_records:
                data.append({
                    'scan_id': record.id,
                    'device_id': record.user.device_id,
                    'object_name': record.user.object_name.name if record.user.object_name else None,
                    'point_name': record.user.point_name,
                    'scan_date': str(record.scan_date),
                    'scan_time': str(record.scan_time),
                    'card_name': record.card_name,
                    'card_surname': record.card_surname,
                    'card_response': record.card_response,
                    'is_valid': record.is_valid,
                })

            return Response({'scan_records': data}, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error fetching scan records: {str(e)}", exc_info=True)
            return Response({'error': 'An unexpected error occurred.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        



class ClockInAndOutView(APIView):
    def post(self, request):
        name = request.data.get('name')
        surname = request.data.get('surname')
        object_name = request.data.get('object_name')
        birthyear = request.data.get('birthyear')
        card_response = request.data.get('card_response')
        action_type = request.data.get('action_type')

        if not all([name, surname, object_name, birthyear, card_response, action_type]):
            logger.warning(f"Missing clock in/out data for {name} {surname} {birthyear}")
            return Response(
                {'error': 'name, surname, object_name, birthyear, card_response, and action_type are required.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if action_type not in ['clock_in', 'clock_out']:
            logger.warning(f"Invalid action_type provided: {action_type}")
            return Response(
                {'error': 'Invalid action_type. Must be either "clock_in" or "clock_out".'},
                status=status.HTTP_400_BAD_REQUEST
            )

        person_filter = Q(name=name, surname=surname, object_name=object_name, birthyear=birthyear)
        last_record = ClockInAndOut.objects.filter(person_filter).order_by('-clock_in_time', '-clock_out_time').first()

        if action_type == 'clock_in':
            if last_record and last_record.action_type == 'clock_in' and last_record.clock_out_time is None:
                logger.warning(f"{name} {surname} attempted to clock in twice consecutively.")
                return Response(
                    {'error': 'You must clock out before clocking in again.'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            elif last_record and last_record.action_type == 'clock_out' and last_record.clock_out_time is not None:
                time_since_last_action = now() - last_record.clock_out_time
                if time_since_last_action.total_seconds() < 10:
                    remaining_seconds = 10 - int(time_since_last_action.total_seconds())
                    logger.warning(f"{name} {surname} attempted to clock in too soon after clocking out.")
                    return Response(
                        {
                            'error': f'You can only clock in after {remaining_seconds} seconds from your last clock-out.',
                            'remaining_time': remaining_seconds
                        },
                        status=status.HTTP_429_TOO_MANY_REQUESTS
                    )

            record = ClockInAndOut.objects.create(
                name=name,
                surname=surname,
                object_name=object_name,
                birthyear=birthyear,
                card_response=card_response,
                clock_in_time=now(),
                action_type='clock_in'
            )
            logger.info(f"Clock in record saved: {record}")

        elif action_type == 'clock_out':
            if not last_record or last_record.action_type != 'clock_in' or last_record.clock_out_time is not None:
                logger.warning(f"{name} {surname} attempted to clock out without clocking in.")
                return Response(
                    {'error': 'You must clock in before clocking out.'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            last_record.clock_out_time = now()
            last_record.action_type = 'clock_out'
            last_record.save()
            record = last_record
            logger.info(f"Clock out record saved: {record}")

        return Response({
            'status': 'success',
            'message': f'Clock {action_type} data saved successfully.',
            'data': {
                'record_id': record.id,
                'name': record.name,
                'surname': record.surname,
                'object_name': record.object_name,
                'birthyear': record.birthyear,
                'card_response': record.card_response,
                'clock_in_time': str(record.clock_in_time),
                'clock_out_time': str(record.clock_out_time) if action_type == 'clock_out' else None,
                'action_type': record.action_type
            }
        }, status=status.HTTP_200_OK)

    def get(self, request):
        try:
            name = request.query_params.get('name')
            surname = request.query_params.get('surname')
            object_name = request.query_params.get('object_name')
            birthyear = request.query_params.get('birthyear')
            record_id = request.query_params.get('record_id')
            date = request.query_params.get('date')

            clock_records = ClockInAndOut.objects.all()

            if record_id:
                clock_records = clock_records.filter(id=record_id)

            if all([name, surname, object_name, birthyear]):
                clock_records = clock_records.filter(
                    name=name, surname=surname, object_name=object_name, birthyear=birthyear
                )

            else:
                if name:
                    clock_records = clock_records.filter(name=name)
                if surname:
                    clock_records = clock_records.filter(surname=surname)
                if object_name:
                    clock_records = clock_records.filter(object_name=object_name)
                if birthyear:
                    clock_records = clock_records.filter(birthyear=birthyear)

            if date:
                clock_records = clock_records.filter(
                    Q(clock_in_time__date=date) | Q(clock_out_time__date=date)
                )

            clock_records = clock_records.order_by('-clock_in_time', '-clock_out_time')

            data = []
            for record in clock_records:
                data.append({
                    'record_id': record.id,
                    'name': record.name,
                    'surname': record.surname,
                    'object_name': record.object_name,
                    'birthyear': record.birthyear,
                    'card_response': record.card_response,
                    'clock_in_time': str(record.clock_in_time),
                    'clock_out_time': str(record.clock_out_time) if record.clock_out_time else None,
                    'action_type': record.action_type
                })

            return Response({'clock_records': data}, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error fetching clock records: {str(e)}", exc_info=True)
            return Response({'error': 'An unexpected error occurred.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)