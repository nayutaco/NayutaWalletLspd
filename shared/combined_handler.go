package shared

type CombinedHandler struct {
	handlers []InterceptHandler
}

func NewCombinedHandler(handlers ...InterceptHandler) *CombinedHandler {
	return &CombinedHandler{
		handlers: handlers,
	}
}

func (c *CombinedHandler) Intercept(req InterceptRequest) InterceptResult {
	for _, handler := range c.handlers {
		res := handler.Intercept(req)
		if res.Action != INTERCEPT_RESUME {
			return res
		}
	}

	return InterceptResult{
		Action: INTERCEPT_RESUME,
	}
}
