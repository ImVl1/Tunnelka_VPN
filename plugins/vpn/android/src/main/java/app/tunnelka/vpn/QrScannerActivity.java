package app.tunnelka.vpn;

import com.journeyapps.barcodescanner.CaptureActivity;
import com.journeyapps.barcodescanner.DecoratedBarcodeView;

public final class QrScannerActivity extends CaptureActivity {
    @Override
    protected DecoratedBarcodeView initializeContent() {
        setContentView(R.layout.qr_scanner);
        findViewById(R.id.scanner_back).setOnClickListener(view -> finish());
        return findViewById(R.id.scanner_preview);
    }
}
