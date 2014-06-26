    public class ErrorService
    {
        public static string GetMessage(string errorCode, params string[] parameters)
        {
            Contract.Requires(!string.IsNullOrWhiteSpace(errorCode));
            string message;
            try
            {
                if (UserErrorConfigSection.Current.Errors[errorCode] == null && !string.IsNullOrEmpty(parameters.FirstOrDefault()))
                {
                    message = parameters.FirstOrDefault();
                    return message;
                }
                message = UserErrorConfigSection.Current.Errors[errorCode].UserMessage;

                if (parameters != null && parameters.Any())
                {
                    message = string.Format(message, parameters);
                }
            }
            catch (TypeInitializationException)
            {
                errorCode = ErrorCode.CannotFoundConfigFileFaiure;
                message = TextResources.CannotFoundConfigFileMsg;
            }
            catch(Exception)
            {
                errorCode = ErrorCode.UnexpectedErrorMsg;
                message = UserErrorConfigSection.Current.Errors[errorCode].UserMessage;
            }
            return message;
        }

        public static void ShowErrorMessageDialogue(string errorCode, params string[] parameters)
        {
            ErrorMessageDialog.Show(errorCode, parameters);
        }

        public static void ShowErrorMessageDialogue(UserFacingException ex)
        {
            ShowErrorMessageDialogue(ex.ErrorCode, ex.Parameters);
        }

        public static void ShowErrorMessageDialogue(Exception ex)
        {
            if (ex is UserFacingException)
                ShowErrorMessageDialogue((UserFacingException)ex);
            else if (ex is FaultException<ValidationFault>)
                ShowErrorMessageDialogue(ErrorCode.ValidationFault);
            else if (ex is FaultException<ServiceFault>)
            {
                FaultException<ServiceFault> fex = (FaultException<ServiceFault>)ex;
                ServiceFault sex = fex.Detail;
                ShowErrorMessageDialogue(sex.ErrorCode.ToString(), sex.ErrorMessage);
            }
            else if (ex is FaultException<VersionFault>)
                ShowErrorMessageDialogue(ErrorCode.VersionIncorrectFaultReasonMessage);
            else if (ex is FaultException)
                ShowErrorMessageDialogue(ErrorCode.ServiceFault);
            else if (ex is CommunicationException)
                ShowErrorMessageDialogue(ErrorCode.ServerUnavailableMsg);
            else if (ex is TimeoutException)
                ShowErrorMessageDialogue(ErrorCode.ServerTimedOutMsg);
            else
                ShowErrorMessageDialogue(ErrorCode.UnexpectedErrorMsg);
        }

        public static async Task<ErrorMessageModel> GetMoreInformationAsync(ErrorMessageModel model)
        {
            ErrorMessageModel result = model;
            try
            {
                var reply = await WorkflowsQueryServiceUtility.InvokeWorkflowQueryServiceAsync((client) =>
                    client.GetErrorMessageAsync(model.ToGetRequest()));
                result = reply.FromDataContract();
            }
            catch(UserFacingException ex)
            {
                result.Suggestion = GetMessage(ex.ErrorCode, ex.Parameters);
            }
            catch(Exception)
            {
                result.Suggestion = GetMessage(ErrorCode.ServerUnavailableMsg);
            }
            return result;
        }

        public static async Task<ErrorMessageSearchReply> SearchErrorMessagesAsync(ErrorMessageSearchRequest request)
        {
            ErrorMessageSearchReply reply = null;
            try
            {
                reply = await WorkflowsQueryServiceUtility.InvokeWorkflowQueryServiceAsync((client) => client.SearchErrorMessageAsync(request));
                reply.StatusReply.CheckErrors();
            }
            catch (Exception ex)
            {
                ShowErrorMessageDialogue(ex);
            }
            return reply;
        }

        public static async Task<bool> UploadErrorMessageAsync(ErrorMessageModel model)
        {
            bool result = true;
            try
            {
                var reply = await WorkflowsQueryServiceUtility.InvokeWorkflowQueryServiceAsync((client) =>
                    client.CreateOrUpdateErrorMessageAsync(model.ToCreateOrUpdateRequest()));
                reply.StatusReply.CheckErrors();
            }
            catch (Exception ex)
            {
                ShowErrorMessageDialogue(ex);
                result = false;
            }
            return result;
        }

        public static void OpenHelpLink(string helpLink)
        {
            Process.Start(helpLink);
        }
    }
