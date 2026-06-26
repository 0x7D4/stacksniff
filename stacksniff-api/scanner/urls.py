from django.urls import include, path
from rest_framework.routers import DefaultRouter

from scanner.views import (
    HealthCheckView,
    ScanJobViewSet,
    ShortcutEndpointsView,
    ShortcutFullView,
    ShortcutSubdomainsView,
    ShortcutTechView,
)

router = DefaultRouter()
router.register(r"scans", ScanJobViewSet, basename="scan")

urlpatterns = [
    path("health/", HealthCheckView.as_view(), name="health-check"),
    path("scan/tech/", ShortcutTechView.as_view()),
    path("scan/full/", ShortcutFullView.as_view()),
    path("scan/endpoints/", ShortcutEndpointsView.as_view()),
    path("scan/subdomains/", ShortcutSubdomainsView.as_view()),
    path("", include(router.urls)),
]
