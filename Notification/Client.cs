        #region Check notifications

        /// <summary>
        /// 
        /// </summary>
        public void InitializeNotificationSystem()
        {
            notificationWindow = new NotificationWindow();
            NotificationsChanged();
            notificationWindow.VM.Notifications.CollectionChanged += (s, e) => { NotificationsChanged(); };
            notificationWindow.VM.Check += new NotificationEventHandler(CheckRefulfillments);
            notificationWindow.VM.Check += new NotificationEventHandler(CheckReAcknowledgement);
            notificationWindow.VM.Check += new NotificationEventHandler(CheckDuplicatedCbr);
            notificationWindow.VM.Check += new NotificationEventHandler(CheckKeysExpired);
            notificationWindow.VM.Check += new NotificationEventHandler(CheckKeyTypeConfigurations);
            notificationWindow.VM.Check += new NotificationEventHandler(CheckOhrData);
            notificationWindow.VM.Check += new NotificationEventHandler(CheckDatabaseDiskFull);
            notificationWindow.VM.Check += new NotificationEventHandler(CheckConfirmedOhrKeys);
            RegisterSystemCheck(configProxy.GetIsAutoDiagnostic());
        }

        private void NotificationsChanged()
        {
            int notificationCount = notificationWindow.VM.Notifications.Count;
            NotificationHeader = string.Format(MergedResources.Notification_YouHaveNotifications, notificationCount);
            if (notificationCount > 0)
            {
                NotificationColor = hasNotifications;
                Dispatch(() =>
                {
                    if (!notificationWindow.VM.ShouldNotificationNotPopup && !notificationWindow.IsVisible && !IsCurrentWindowBusy())
                        OnOpenNotification();
                });
            }
            else
            {
                NotificationColor = hasNoNotification;
            }
        }

        private void CheckOhrData(object sender, NotificationEventArgs e)
        {
            try
            {
                NotificationCategory category = NotificationCategory.OhrDataMissed;
                if (configProxy.GetRequireOHRData())
                {
                    List<KeyInfo> keys = keyProxy.GetBoundKeysWithoutOhrData();
                    Dispatch(() =>
                    {
                        if (keys != null && keys.Any())
                            e.Push(new Notification(category,
                                string.Format(ResourcesOfRTMv1_6.OhrDataMissedFormat, keys.Count),
                                typeof(EditKeysOptionalInfo), () =>
                                {
                                    CheckOhrData(sender, e);
                                    OnRefreshKeys();
                                }, keyProxy, keys, false));
                        else
                            e.Pop(category);
                    });
                }
                else
                    e.Pop(category);
            }
            catch (Exception ex)
            {
                MessageLogger.LogSystemError(MessageLogger.GetMethodName(), ex.GetTraceText());
            }
        }

        private void CheckKeyTypeConfigurations(object sender, NotificationEventArgs e)
        {
            try
            {
                List<KeyTypeConfiguration> configs = stockProxy.GetKeyTypeConfigurations(KmtConstants.HeadQuarterId);
                Dispatch(() =>
                {
                    NotificationCategory keyTypeUnmappedCategory = NotificationCategory.KeyTypeUnmapped;
                    if (configs.Any(c => !c.KeyType.HasValue))
                        e.Push(new Notification(keyTypeUnmappedCategory,
                            ResourcesOfR6.Notification_UpmapKeyPartNumber,
                            typeof(ConfigurationView),
                            () =>
                            {
                                CheckKeyTypeConfigurations(sender, e);
                                OnRefreshKeys();
                            },
                            configProxy, ssProxy, hqProxy, userProxy, null, keyProxy, 2));
                    else
                        e.Pop(keyTypeUnmappedCategory);

                    NotificationCategory quantityOutOfRangeCategory = NotificationCategory.QuantityOutOfRange;
                    List<KeyTypeConfiguration> configsOutOfRange = configs.Where(c => c.AvailiableKeysCount < c.Minimum || c.AvailiableKeysCount > c.Maximum).ToList();
                    if (configsOutOfRange.Count > 0)
                        e.Push(new Notification(quantityOutOfRangeCategory,
                            string.Format(MergedResources.Notification_KeysStockOutOfRangeMessage, configsOutOfRange.Count),
                            typeof(KeysStockNotificationView), null, configsOutOfRange));
                    else
                        e.Pop(quantityOutOfRangeCategory);
                });
            }
            catch (Exception ex)
            {
                MessageLogger.LogSystemError(MessageLogger.GetMethodName(), ex.GetTraceText());
            }
        }

        private void CheckRefulfillments(object sender, NotificationEventArgs e)
        {
            try
            {
                NotificationCategory category = NotificationCategory.ReFulfillment;
                List<FulfillmentInfo> infoes = keyProxy.GetFailedFulfillments(false);
                Dispatch(() =>
                {
                    if (infoes.Count > 0)
                        e.Push(new Notification(category,
                            string.Format(MergedResources.Notification_ReFulfillmentMessage, infoes.Count),
                            typeof(ReFulfillmentNotificationView), null, infoes, keyProxy));
                    else
                        e.Pop(category);
                });
            }
            catch (Exception ex)
            {
                MessageLogger.LogSystemError(MessageLogger.GetMethodName(), ex.GetTraceText());
            }
        }

        private void CheckReAcknowledgement(object sender, NotificationEventArgs e)
        {
            try
            {
                NotificationCategory category = NotificationCategory.ReAcknowledgement;
                List<Cbr> cbrs = keyProxy.GetFailedCbrs();
                Dispatch(() =>
                {
                    if (cbrs.Count > 0)
                        e.Push(new Notification(category,
                            string.Format(MergedResources.Notification_ReAcknowledgeMessage, cbrs.Count),
                            typeof(ReAcknowledgementNotificationView), null, cbrs));
                    else
                        e.Pop(category);
                });
            }
            catch (Exception ex)
            {
                MessageLogger.LogSystemError(MessageLogger.GetMethodName(), ex.GetTraceText());
            }
        }

        private void CheckDuplicatedCbr(object sender, NotificationEventArgs e)
        {
            try
            {
                NotificationCategory category = NotificationCategory.DuplicatedCbr;
                List<Cbr> cbrs = keyProxy.GetCbrsDuplicated().FindAll(cbr => cbr.CbrDuplicated != null);
                cbrs.ForEach(cbr =>
                {
                    Dispatch(() =>
                    {
                        if (cbrs.Count > 0)
                            e.Push(new Notification(category,
                                string.Format(MergedResources.ExportDuplicateCBRNotificationViewModel_DuplicateCBRsMessage, cbr.CbrKeys.Count),
                                typeof(ExportDuplicateCBRNotificationView), () => { CheckDuplicatedCbr(sender, e); }, cbr, keyProxy));
                        else
                            e.Pop(category);
                    });
                });


            }
            catch (Exception ex)
            {
                MessageLogger.LogSystemError(MessageLogger.GetMethodName(), ex.GetTraceText());
            }
        }

        private void CheckKeysExpired(object sender, NotificationEventArgs e)
        {
            try
            {
                NotificationCategory category = NotificationCategory.OldTimelineExceed;
                List<KeyInfo> keysExpired = keyProxy.SearchExpiredKeys(KmtConstants.OldTimeline);
                Dispatch(() =>
                {
                    if (keysExpired.Count > 0)
                        e.Push(new Notification(category,
                            string.Format(MergedResources.KeyManagementViewModel_OldTimelineExceedMessage, keysExpired.Count),
                            typeof(KeysExpiredNotificationView), null, keysExpired, KmtConstants.OldTimeline));
                    else
                        e.Pop(category);
                });
            }
            catch (Exception ex)
            {
                MessageLogger.LogSystemError(MessageLogger.GetMethodName(), ex.GetTraceText());
            }
        }

        private void CheckConfirmedOhrKeys(object sender, NotificationEventArgs e)
        {
            try
            {
                NotificationCategory category = NotificationCategory.ConfirmedOhrs;
                List<Ohr> ohrs = keyProxy.GetConfirmedOhrs();
                Dispatch(() =>
                {
                    if (ohrs.Count > 0)
                        e.Push(new Notification(category,
                            ResourcesOfRTMv1_8.OhrUpdateViewModel_Message,
                            typeof(OhrKeysNotificationView), 
                            () => 
                                {
                                    keyProxy.UpdateOhrAfterNotification(ohrs);
                                }, ohrs, keyProxy));
                    else
                        e.Pop(category);
                });
            }
            catch (Exception ex)
            {
                MessageLogger.LogSystemError(MessageLogger.GetMethodName(), ex.GetTraceText());
            }
        }

        private void CheckDatabaseDiskFull(object sender, NotificationEventArgs e)
        {
            try
            {
                NotificationCategory category = NotificationCategory.SystemError_DabaseDiskFull;
                DiagnosticResult result = configProxy.TestDatabaseDiskFull();
                Dispatch(() =>
                {
                    if (result.DiagnosticResultType == DiagnosticResultType.Error)
                    {
                        Notification no = new Notification(category,
                            ResourcesOfRTMv1_8.Notification_DatabaseDiskFull,
                            null, () => {
                                configProxy.DatabaseDiskFullReport();
                                e.Pop(category);
                            }, null);
                        no.ButtonContent = MergedResources.Common_Clear;
                        e.Push(no);
                    }
                    else
                        e.Pop(category);
                });
            }
            catch (Exception ex)
            {
                MessageLogger.LogSystemError(MessageLogger.GetMethodName(), ex.GetTraceText());
            }
        }

        private bool IsCurrentWindowBusy()
        {
            try
            {
                dynamic current = null;
                WindowCollection windows = App.Current.Windows;
                for (int i = 0; i < windows.Count; i++)
                {
                    if (!(windows[windows.Count - 1 - i] is NotificationWindow))
                    {
                        current = windows[windows.Count - 1 - i];
                        break;
                    }
                }
                return current.VM.IsBusy;
            }
            catch (RuntimeBinderException)
            {
                return false;
            }
        }

        #endregion

        #region System state notifications

        /// <summary>
        /// Register system state check
        /// </summary>
        /// <param name="enabled"></param>
        private void RegisterSystemCheck(bool enabled)
        {
            if (enabled)
                notificationWindow.VM.SystemCheck += OnCheckSystemStatus;
            else
            {
                notificationWindow.VM.SystemCheck -= OnCheckSystemStatus;
                PopSystemErrorOnUnCheckSystemStatus();
            }
        }

        private void PopSystemErrorOnUnCheckSystemStatus()
        {
            Dispatch(() =>
            {
                ObservableCollection<Notification> notifications = notificationWindow.VM.Notifications;
                NotificationCategory[] systemNotifications = new NotificationCategory[]
                {
                    NotificationCategory.SystemError_DatePolling,
                    NotificationCategory.SystemError_DownLevelSystem,
                    NotificationCategory.SystemError_Internal,
                    NotificationCategory.SystemError_MSConnection,
                    NotificationCategory.SystemError_UpLevelSystem,
                    NotificationCategory.SystemError_Unknow,
                    NotificationCategory.SystemError_DataBaseError,
                    NotificationCategory.SystemError_KeyProviderServiceError,
                };
                var removed = notifications.Where(n => systemNotifications.Contains(n.Category)).ToList();

                foreach (var systemError in removed)
                {
                    notifications.Remove(systemError);
                }
            });
        }

        private void OnCheckSystemStatus(object sender, NotificationEventArgs e)
        {
            CheckDatabaseSystemState(sender, e);
            CheckInternalSystemState(sender, e);
            CheckDataPollingSystemState(sender, e);

            if (KmtConstants.IsFactoryFloor)
                CheckKeyProviderServiceSystemState(sender, e);
        }

        /// <summary>
        /// test database
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void CheckDatabaseSystemState(object sender, NotificationEventArgs e)
        {
            var result = configProxy.TestDatabaseConnection();
            SetSystemState(NotificationCategory.SystemError_DataBaseError, result, ResourcesOfR6.Notification_DataBaseErrorMessage, e);
        }

        /// <summary>
        ///test Internal web service
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void CheckInternalSystemState(object sender, NotificationEventArgs e)
        {
            string errorMessage = string.Empty;
            internalDiagnosticResult = configProxy.TestInternalConnection();
            SetSystemState(NotificationCategory.SystemError_Internal, internalDiagnosticResult, ResourcesOfR6.Notification_InternalErrorMessage, e);
        }

        /// <summary>
        /// test data polling
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void CheckDataPollingSystemState(object sender, NotificationEventArgs e)
        {
            if (!IsUnknownError(NotificationCategory.SystemError_DatePolling, ResourcesOfR6.Notification_DatePollingErrorMessage, e))
            {
                string errorMessage = string.Empty;
                var result = configProxy.TestDataPollingService();
                SetSystemState(NotificationCategory.SystemError_DatePolling, result, ResourcesOfR6.Notification_DatePollingErrorMessage, e);
            }
        }

        /// <summary>
        /// test key provider service
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void CheckKeyProviderServiceSystemState(object sender, NotificationEventArgs e)
        {
            if (!IsUnknownError(NotificationCategory.SystemError_KeyProviderServiceError, ResourcesOfR6.Notification_KeyProviderServiceErrorMessage, e))
            {
                var result = configProxy.TestKeyProviderService();
                SetSystemState(NotificationCategory.SystemError_KeyProviderServiceError, result, ResourcesOfR6.Notification_KeyProviderServiceErrorMessage, e);
            }
        }

        /// <summary>
        /// Set error when internal web service dose not work
        /// </summary>
        /// <param name="e"></param>
        private bool IsUnknownError(NotificationCategory notificationCategory, string errorTitle, NotificationEventArgs e)
        {
            if (internalDiagnosticResult.DiagnosticResultType == DiagnosticResultType.Error)
            {
                SetSystemState(notificationCategory, new DiagnosticResult()
                {
                    Exception = null,
                    DiagnosticResultType = DiagnosticResultType.Error
                },
                    errorTitle,
                    e);
                return true;
            }
            else
            {
                return false;
            }
        }

        /// <summary>
        /// create system state notification
        /// </summary>
        /// <param name="diagnosticResult"></param>
        /// <param name="errorTitle"></param>
        /// <param name="e"></param>
        private void SetSystemState(NotificationCategory notificationCategory, DiagnosticResult diagnosticResult, string errorTitle, NotificationEventArgs e)
        {
            try
            {
                NotificationCategory category = notificationCategory;
                string errorMessage = null;
                Dispatch(() =>
                {
                    if ((category != NotificationCategory.SystemError_KeyProviderServiceError && category != NotificationCategory.SystemError_DatePolling) || diagnosticResult.Exception == null)
                        errorMessage = diagnosticResult.Exception == null ? ResourcesOfR6.Notification_UnknowMessage : diagnosticResult.Exception.ToString();

                    if (diagnosticResult.DiagnosticResultType == DiagnosticResultType.Error)
                        e.Push(new Notification(category,
                            errorTitle,
                            string.IsNullOrEmpty(errorMessage) ? null : typeof(SystemStateNotificationView), null, errorTitle, errorMessage));
                    else
                        e.Pop(category);
                });

            }
            catch (Exception ex)
            {
                MessageLogger.LogSystemError(MessageLogger.GetMethodName(), ex.GetTraceText());
            }
        }

        #endregion
