package com.integra.usbtokensign;
/**
*
* @author Shashidhara
*/

import java.io.IOException;

import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.common.PDStream;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.graphics.form.PDFormXObject;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceDictionary;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceStream;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.json.JSONException;

public class AddVisibleSignature {

	public static void createVisualSignatureTemplate(PDDocument srcDoc, PDSignatureField signatureField, PDPage pageNum,
			PDRectangle rect, PDImageXObject pdImage, String signDisplayInfo) throws IOException, JSONException {
		String[] signInfo = signDisplayInfo.split("\n");

		// from PDVisualSigBuilder.createHolderForm()
		PDStream stream = new PDStream(srcDoc);
		PDFormXObject form = new PDFormXObject(stream);
		PDResources res = new PDResources();
		form.setResources(res);
		form.setFormType(1);

		PDRectangle bbox = new PDRectangle(rect.getWidth(), rect.getHeight());
		float height = bbox.getHeight();
		form.setBBox(bbox);

		PDFont font = PDType1Font.TIMES_ROMAN;

		// from PDVisualSigBuilder.createAppearanceDictionary()
		PDAppearanceDictionary appearance = new PDAppearanceDictionary();
		appearance.getCOSObject().setDirect(true);
		PDAppearanceStream appearanceStream = new PDAppearanceStream(form.getCOSObject());
		appearance.setNormalAppearance(appearanceStream);

		PDAnnotationWidget widget = signatureField.getWidgets().get(0);
		widget.setRectangle(rect);
		widget.setAppearance(appearance);
		widget.setPage(pageNum);

		try (PDPageContentStream cs = new PDPageContentStream(srcDoc, appearanceStream)) {
			cs.saveGraphicsState();
			cs.drawImage(pdImage, 0, 0, rect.getWidth(), rect.getHeight());
			cs.restoreGraphicsState();

			// show text
			float fontSize = 8;
			float leading = fontSize * 1.2f;
			cs.beginText();
			cs.setFont(font, fontSize);
			cs.newLineAtOffset(3, height - 20);
			cs.setLeading(leading);
			for (String str : signInfo) {
				cs.showText(str);
				cs.newLine();
			}
			cs.endText();
			cs.fill();
			cs.close();
		}catch (Exception e) {
			e.printStackTrace();
		}

		pageNum.getAnnotations().add(widget);

		COSDictionary pageTreeObject = pageNum.getCOSObject();
		while (pageTreeObject != null) {
			pageTreeObject.setNeedToBeUpdated(true);
			pageTreeObject = (COSDictionary) pageTreeObject.getDictionaryObject(COSName.PARENT);
		}
	}

}
