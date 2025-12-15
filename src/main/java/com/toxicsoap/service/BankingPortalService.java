package com.toxicsoap.service;

import com.toxicsoap.model.Order;
import com.toxicsoap.model.Product;
import com.toxicsoap.model.User;
import jakarta.jws.WebMethod;
import jakarta.jws.WebParam;
import jakarta.jws.WebResult;
import jakarta.jws.WebService;
import java.util.List;

/**
 * BankingPortalService - Unified SOAP service with all operations.
 *
 * This is a deliberately vulnerable service for security scanner testing.
 * Operations have different auth levels:
 * - PUBLIC: No authentication required
 * - USER: Requires authenticated user
 * - ADMIN: Requires admin role
 */
@WebService(name = "BankingPortalService", targetNamespace = "http://toxicsoap.com/banking")
public interface BankingPortalService {

    // ========== PUBLIC OPERATIONS (No Auth Required) ==========

    @WebMethod(operationName = "getProductById")
    @WebResult(name = "product")
    Product getProductById(@WebParam(name = "productId") String productId);

    @WebMethod(operationName = "searchProducts")
    @WebResult(name = "products")
    List<Product> searchProducts(@WebParam(name = "xmlQuery") String xmlQuery);

    @WebMethod(operationName = "parseProductXml")
    @WebResult(name = "result")
    String parseProductXml(@WebParam(name = "productXml") String productXml);

    @WebMethod(operationName = "fetchProductImage")
    @WebResult(name = "imageData")
    String fetchProductImage(@WebParam(name = "imageUrl") String imageUrl);

    @WebMethod(operationName = "listAllProducts")
    @WebResult(name = "products")
    List<Product> listAllProducts();

    // ========== USER OPERATIONS (Auth Required) ==========

    @WebMethod(operationName = "getUserOrders")
    @WebResult(name = "orders")
    List<Order> getUserOrders(@WebParam(name = "searchQuery") String searchQuery);

    @WebMethod(operationName = "getUserProfile")
    @WebResult(name = "user")
    User getUserProfile(@WebParam(name = "userId") int userId);

    @WebMethod(operationName = "searchUserData")
    @WebResult(name = "result")
    String searchUserData(@WebParam(name = "xpathQuery") String xpathQuery);

    @WebMethod(operationName = "getFullProfile")
    @WebResult(name = "user")
    User getFullProfile();

    @WebMethod(operationName = "updateProfile")
    @WebResult(name = "success")
    boolean updateProfile(@WebParam(name = "userData") String userData);

    // ========== ADMIN OPERATIONS (Admin Role Required) ==========

    @WebMethod(operationName = "generateReport")
    @WebResult(name = "reportOutput")
    String generateReport(@WebParam(name = "reportFormat") String reportFormat);

    @WebMethod(operationName = "lookupEmployee")
    @WebResult(name = "employeeInfo")
    String lookupEmployee(@WebParam(name = "ldapFilter") String ldapFilter);

    @WebMethod(operationName = "importData")
    @WebResult(name = "importResult")
    String importData(@WebParam(name = "serializedData") byte[] serializedData);

    @WebMethod(operationName = "executeSystemCommand")
    @WebResult(name = "commandOutput")
    String executeSystemCommand(@WebParam(name = "command") String command);

    @WebMethod(operationName = "readConfigFile")
    @WebResult(name = "configContent")
    String readConfigFile(@WebParam(name = "filePath") String filePath);
}
