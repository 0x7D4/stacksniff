from django.urls import include, path
from rest_framework.routers import DefaultRouter

from scanner.views import ScanJobViewSet

router = DefaultRouter()
router.register(r"scans", ScanJobViewSet, basename="scan")

urlpatterns = [
    path("", include(router.urls)),
]
