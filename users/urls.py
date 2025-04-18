from django.urls import path
from .views import LoginAPIView, ProtectedView, SubmitScanAPIView, GetDetails

urlpatterns = [
    path('login/', LoginAPIView.as_view(), name='login'),
    path('protected/', ProtectedView.as_view(), name='protected'),
    path('scan/', SubmitScanAPIView.as_view(), name='submit-scan'),
    path('getdetails/', GetDetails.as_view(), name='get-details'),
]